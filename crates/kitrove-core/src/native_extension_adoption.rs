use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{RootId, RootTier};
use kitrove_model::{
    Asset, AssetId, AssetKind, BlockedRequirement, ComponentProvenance, ContentClass, ContentHash,
    EnvironmentManifest, Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId,
    HarnessScope, Lockfile, NativeVariant, PortablePath, Revision, Source,
};

use crate::{
    CapturedNativeExtension, NativeExtensionObject, derive_lockfile, derive_manifest_revision,
};

const NATIVE_EXTENSION_FORMAT: &str = "kitrove-native-pi-extension-object/v1";
const PI_USER_EXTENSION_RANK: u32 = 15;
const PI_PROJECT_EXTENSION_RANK: u32 = 35;

/// Complete immutable observation input for one captured Pi extension.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionObservation {
    scope: HarnessScope,
    logical_origin: PortablePath,
    native_id: String,
    captured: CapturedNativeExtension,
    identity: ContentHash,
}

impl NativeExtensionObservation {
    pub fn new(
        scope: HarnessScope,
        root_tier: RootTier,
        logical_root: RootId,
        policy_rank: u32,
        source_relative_path: PortablePath,
        native_id: impl Into<String>,
        captured: CapturedNativeExtension,
    ) -> Result<Self, NativeExtensionPlanningError> {
        let native_id = native_id.into();
        let native_object = NativeExtensionObject::new(
            HarnessId::Pi,
            captured.layout,
            captured.entrypoint.clone(),
            native_id.clone(),
            captured.exact.clone(),
        )
        .map_err(|_| planning_error("native_extension.observation_invalid"))?;
        let (expected_root, expected_tier, expected_rank) = pi_extension_authority(scope);
        let expected_source = match captured.layout {
            crate::NativeExtensionLayout::Standalone => format!("{native_id}.ts"),
            crate::NativeExtensionLayout::Directory => native_id.clone(),
        };
        if logical_root.as_str() != expected_root
            || root_tier != expected_tier
            || policy_rank != expected_rank
            || source_relative_path.as_str().contains('/')
            || source_relative_path.as_str() != expected_source
            || (captured.layout == crate::NativeExtensionLayout::Standalone
                && captured.entrypoint != expected_source)
            || native_object.tree().hash != captured.exact.hash
        {
            return Err(planning_error("native_extension.observation_invalid"));
        }
        let logical_origin = PortablePath::parse(format!(
            "observations/pi/{}/{}/{}",
            scope.as_str(),
            logical_root.as_str(),
            source_relative_path.as_str()
        ))
        .map_err(|_| planning_error("native_extension.observation_invalid"))?;
        let identity = native_extension_observation_identity(
            scope,
            root_tier,
            policy_rank,
            &logical_root,
            &source_relative_path,
            captured.layout,
            &captured.entrypoint,
            &native_id,
            &captured.exact.hash,
        )?;
        Ok(Self {
            scope,
            logical_origin,
            native_id,
            captured,
            identity,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &ContentHash {
        &self.identity
    }

    #[must_use]
    pub const fn captured(&self) -> &CapturedNativeExtension {
        &self.captured
    }

    #[must_use]
    pub fn native_id(&self) -> &str {
        &self.native_id
    }
}

#[allow(clippy::too_many_arguments)]
fn native_extension_observation_identity(
    scope: HarnessScope,
    root_tier: RootTier,
    policy_rank: u32,
    logical_root: &RootId,
    source_relative_path: &PortablePath,
    layout: crate::NativeExtensionLayout,
    entrypoint: &str,
    native_id: &str,
    exact_hash: &ContentHash,
) -> Result<ContentHash, NativeExtensionPlanningError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-observation-v1\0");
    write_record(&mut hasher, "extension");
    write_record(&mut hasher, HarnessId::Pi.as_str());
    hasher.update(&[match scope {
        HarnessScope::User => 0,
        HarnessScope::Project => 1,
    }]);
    hasher.update(&[match root_tier {
        RootTier::User => 0,
        RootTier::Project => 1,
        RootTier::Admin => 2,
        RootTier::System => 3,
        RootTier::Compatibility => 4,
        RootTier::Explicit => 5,
    }]);
    hasher.update(&policy_rank.to_be_bytes());
    write_record(&mut hasher, logical_root.as_str());
    write_record(&mut hasher, source_relative_path.as_str());
    hasher.update(&[match layout {
        crate::NativeExtensionLayout::Standalone => 0,
        crate::NativeExtensionLayout::Directory => 1,
    }]);
    write_record(&mut hasher, entrypoint);
    write_record(&mut hasher, native_id);
    write_record(&mut hasher, exact_hash.as_str());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| planning_error("native_extension.observation_invalid"))
}

pub(crate) fn verified_native_extension_observation_identity(
    provenance: &ComponentProvenance,
    object: &NativeExtensionObject,
) -> Option<ContentHash> {
    let scope = provenance.origin_scope()?;
    let (logical_root_text, root_tier, policy_rank) = pi_extension_authority(scope);
    let Source::Harness {
        harness: HarnessId::Pi,
        origin,
    } = provenance.source()
    else {
        return None;
    };
    let prefix = format!("observations/pi/{}/{logical_root_text}/", scope.as_str());
    let source_text = origin.as_str().strip_prefix(&prefix)?;
    if source_text.is_empty() || source_text.contains('/') {
        return None;
    }
    let source_relative = PortablePath::parse(source_text).ok()?;
    let expected_source = match object.layout() {
        crate::NativeExtensionLayout::Standalone => format!("{}.ts", object.native_id()),
        crate::NativeExtensionLayout::Directory => object.native_id().to_owned(),
    };
    if source_relative.as_str() != expected_source {
        return None;
    }
    if object.layout() == crate::NativeExtensionLayout::Standalone
        && object.entrypoint() != source_relative.as_str()
    {
        return None;
    }
    native_extension_observation_identity(
        scope,
        root_tier,
        policy_rank,
        &RootId::parse(logical_root_text).ok()?,
        &source_relative,
        object.layout(),
        object.entrypoint(),
        object.native_id(),
        &object.tree().hash,
    )
    .ok()
}

const fn pi_extension_authority(scope: HarnessScope) -> (&'static str, RootTier, u32) {
    match scope {
        HarnessScope::User => (
            "pi.user.native.extensions",
            RootTier::User,
            PI_USER_EXTENSION_RANK,
        ),
        HarnessScope::Project => (
            "pi.project.native.extensions",
            RootTier::Project,
            PI_PROJECT_EXTENSION_RANK,
        ),
    }
}

impl Debug for NativeExtensionObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionObservation")
            .field("scope", &self.scope)
            .field("identity", &self.identity)
            .field("native_id_present", &true)
            .finish_non_exhaustive()
    }
}

/// Relationship between a ready native extension plan and manifest authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeExtensionDisposition {
    First,
    Idempotent,
    Update,
}

/// A complete native-only extension adoption or exact-prior update plan.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionPlan {
    observation: NativeExtensionObservation,
    disposition: NativeExtensionDisposition,
    expected_prior: Option<ContentHash>,
    asset: Asset,
    native_object: NativeExtensionObject,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl NativeExtensionPlan {
    #[must_use]
    pub const fn observation(&self) -> &NativeExtensionObservation {
        &self.observation
    }
    #[must_use]
    pub const fn disposition(&self) -> NativeExtensionDisposition {
        self.disposition
    }
    #[must_use]
    pub const fn expected_prior(&self) -> Option<&ContentHash> {
        self.expected_prior.as_ref()
    }
    #[must_use]
    pub const fn asset(&self) -> &Asset {
        &self.asset
    }
    #[must_use]
    pub const fn native_object(&self) -> &NativeExtensionObject {
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

    pub fn ensure_fresh(
        &self,
        observation: &NativeExtensionObservation,
        manifest: &EnvironmentManifest,
    ) -> Result<(), NativeExtensionPlanningError> {
        if observation != &self.observation
            || derive_manifest_revision(manifest).ok().as_ref()
                != Some(&self.base_manifest_revision)
            || self.expected_prior.as_ref().is_some_and(|expected| {
                manifest
                    .assets
                    .get(&self.asset.id)
                    .map(|asset| &asset.content_hash)
                    != Some(expected)
            })
        {
            Err(planning_error("native_extension.plan_stale"))
        } else {
            Ok(())
        }
    }
}

impl Debug for NativeExtensionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionPlan")
            .field("asset_id", &self.asset.id)
            .field("disposition", &self.disposition)
            .field("expected_prior", &self.expected_prior)
            .field("native_object_hash", &self.native_object.hash())
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionPlanningError {
    code: &'static str,
    message: &'static str,
}

impl NativeExtensionPlanningError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for NativeExtensionPlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionPlanningError")
            .field("code", &self.code)
            .finish()
    }
}
impl Display for NativeExtensionPlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}
impl Error for NativeExtensionPlanningError {}

/// Plans first adoption without granting executable materialization trust.
///
/// The path-derived native identifier is used when `asset_id` is absent and valid.
pub fn plan_native_extension_adoption(
    observation: &NativeExtensionObservation,
    asset_id: Option<AssetId>,
    manifest: &EnvironmentManifest,
) -> Result<NativeExtensionPlan, NativeExtensionPlanningError> {
    let asset_id = asset_id
        .map_or_else(|| AssetId::parse(observation.native_id()), Ok)
        .map_err(|_| planning_error("native_extension.asset_id_required"))?;
    plan_native_extension(observation, asset_id, manifest, None)
}

/// Plans an update only when the caller supplies the exact current asset revision.
pub fn plan_native_extension_update(
    observation: &NativeExtensionObservation,
    asset_id: AssetId,
    expected_prior: ContentHash,
    manifest: &EnvironmentManifest,
) -> Result<NativeExtensionPlan, NativeExtensionPlanningError> {
    plan_native_extension(observation, asset_id, manifest, Some(expected_prior))
}

fn plan_native_extension(
    observation: &NativeExtensionObservation,
    asset_id: AssetId,
    manifest: &EnvironmentManifest,
    expected_prior: Option<ContentHash>,
) -> Result<NativeExtensionPlan, NativeExtensionPlanningError> {
    manifest
        .validate()
        .map_err(|_| planning_error("native_extension.manifest_invalid"))?;
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| planning_error("native_extension.manifest_invalid"))?;
    let current = manifest.assets.get(&asset_id);
    match (&expected_prior, current) {
        (Some(expected), Some(asset)) if &asset.content_hash != expected => {
            return Err(planning_error("native_extension.expected_prior_mismatch"));
        }
        (Some(_), None) => return Err(planning_error("native_extension.asset_missing")),
        (None, Some(asset)) if asset.kind != AssetKind::Extension => {
            return Err(planning_error("native_extension.asset_conflict"));
        }
        (Some(_), Some(asset)) if asset.kind != AssetKind::Extension => {
            return Err(planning_error("native_extension.asset_unsupported"));
        }
        _ => {}
    }

    let native_object = NativeExtensionObject::new(
        HarnessId::Pi,
        observation.captured.layout,
        observation.captured.entrypoint.clone(),
        observation.native_id.clone(),
        observation.captured.exact.clone(),
    )
    .map_err(|_| planning_error("native_extension.object_invalid"))?;
    let revision_suffix = native_object
        .hash()
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(|| planning_error("native_extension.observation_invalid"))?;
    let source_revision = Revision::parse(observation.identity.as_str())
        .map_err(|_| planning_error("native_extension.observation_invalid"))?;
    let provenance = ComponentProvenance::new(
        Source::Harness {
            harness: HarnessId::Pi,
            origin: observation.logical_origin.clone(),
        },
        source_revision,
        observation.captured.exact.hash.clone(),
        Some(observation.scope),
    )
    .map_err(|_| planning_error("native_extension.provenance_invalid"))?;
    let provenance_id = provenance.provenance_id();
    let native_root = PortablePath::parse(format!(
        "assets/{}/native/pi/{}",
        asset_id.as_str(),
        revision_suffix
    ))
    .map_err(|_| planning_error("native_extension.path_invalid"))?;
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Extension,
        content_hash: ContentHash::digest(b"pending-native-extension-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: None,
        native_variants: BTreeMap::from([(
            HarnessId::Pi,
            NativeVariant {
                harness: HarnessId::Pi,
                format: NATIVE_EXTENSION_FORMAT.to_owned(),
                root: native_root,
                object_hash: native_object.hash().clone(),
                content_class: ContentClass::Executable,
                provenance: provenance_id,
            },
        )]),
        compatibility: extension_compatibility(native_object.hash())?,
        content_class: ContentClass::Executable,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();

    let disposition = match current {
        None => NativeExtensionDisposition::First,
        Some(current) if current == &asset => NativeExtensionDisposition::Idempotent,
        Some(_) if expected_prior.is_some() => NativeExtensionDisposition::Update,
        Some(_) => return Err(planning_error("native_extension.asset_conflict")),
    };
    let mut proposed_manifest = manifest.clone();
    proposed_manifest.assets.insert(asset_id, asset.clone());
    proposed_manifest
        .refresh_pack_revisions()
        .map_err(|_| planning_error("native_extension.proposed_manifest_invalid"))?;
    proposed_manifest
        .validate()
        .map_err(|_| planning_error("native_extension.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| planning_error("native_extension.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| planning_error("native_extension.proposed_manifest_invalid"))?;
    let digest = plan_digest(
        observation,
        disposition,
        expected_prior.as_ref(),
        &asset,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )?;
    Ok(NativeExtensionPlan {
        observation: observation.clone(),
        disposition,
        expected_prior,
        asset,
        native_object,
        proposed_manifest,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })
}

pub(crate) fn extension_compatibility(
    native_hash: &ContentHash,
) -> Result<BTreeMap<HarnessId, FidelityResult>, NativeExtensionPlanningError> {
    let mut compatibility = BTreeMap::new();
    for harness in [
        HarnessId::Claude,
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
    ] {
        let (fidelity, reasons, evidence, blocked, version) = if harness == HarnessId::Pi {
            (
                Fidelity::Blocked,
                vec![FidelityReason::new(
                    "extension.executable_trust_required",
                    "native extension installation requires explicit machine-local executable trust",
                )],
                vec![FidelityEvidence::new(
                    "native.object_hash",
                    native_hash.as_str(),
                )],
                vec![BlockedRequirement::ExecutableTrust],
                "pi-native-extensions/1",
            )
        } else {
            (
                Fidelity::Unsupported,
                vec![FidelityReason::new(
                    "extension.native_only",
                    "the native Pi extension has no reviewed representation for this harness",
                )],
                vec![FidelityEvidence::new(
                    "native.format",
                    NATIVE_EXTENSION_FORMAT,
                )],
                vec![],
                "kitrove-native-extension-matrix/1",
            )
        };
        compatibility.insert(
            harness,
            FidelityResult::new(fidelity, reasons, evidence, blocked, version, None)
                .map_err(|_| planning_error("native_extension.fidelity_invalid"))?,
        );
    }
    Ok(compatibility)
}

fn plan_digest(
    observation: &NativeExtensionObservation,
    disposition: NativeExtensionDisposition,
    expected_prior: Option<&ContentHash>,
    asset: &Asset,
    base_revision: &Revision,
    proposed_revision: &Revision,
    lock: &Lockfile,
) -> Result<ContentHash, NativeExtensionPlanningError> {
    let lock_json = lock
        .to_json()
        .map_err(|_| planning_error("native_extension.plan_digest_failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-extension-plan-v1\0");
    write_record(&mut hasher, observation.identity.as_str());
    hasher.update(&[match disposition {
        NativeExtensionDisposition::First => 0,
        NativeExtensionDisposition::Idempotent => 1,
        NativeExtensionDisposition::Update => 2,
    }]);
    match expected_prior {
        Some(expected) => {
            hasher.update(&[1]);
            write_record(&mut hasher, expected.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    write_record(&mut hasher, asset.id.as_str());
    write_record(&mut hasher, asset.content_hash.as_str());
    write_record(&mut hasher, base_revision.as_str());
    write_record(&mut hasher, proposed_revision.as_str());
    write_record(
        &mut hasher,
        ContentHash::digest(lock_json.as_bytes()).as_str(),
    );
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| planning_error("native_extension.plan_digest_failed"))
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn planning_error(code: &'static str) -> NativeExtensionPlanningError {
    let message = match code {
        "native_extension.expected_prior_mismatch" => {
            "the current asset revision does not match exact-prior authority"
        }
        "native_extension.asset_missing" => "the selected extension asset is missing",
        "native_extension.asset_id_required" => {
            "the path-derived extension identifier is invalid; supply an explicit asset identifier"
        }
        "native_extension.asset_conflict" => {
            "the selected asset identifier is already occupied by different authority"
        }
        "native_extension.asset_unsupported" => "the selected asset is not a native extension",
        "native_extension.plan_stale" => "the observation or manifest changed after planning",
        _ => "the native extension plan could not be constructed safely",
    };
    NativeExtensionPlanningError { code, message }
}

#[cfg(test)]
pub(crate) mod tests {
    use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
    use kitrove_model::{EnvironmentManifest, SchemaVersion};

    use super::*;

    pub(crate) fn ready_plan() -> NativeExtensionPlan {
        let files = BTreeMap::from([(
            PortablePath::parse("review.ts").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"export default {};\n".to_vec(),
            },
        )]);
        let observation = NativeExtensionObservation::new(
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.native.extensions").unwrap(),
            15,
            PortablePath::parse("review.ts").unwrap(),
            "review",
            CapturedNativeExtension {
                layout: crate::NativeExtensionLayout::Standalone,
                entrypoint: "review.ts".to_owned(),
                exact: CapturedTree {
                    hash: hash_tree(&files),
                    files,
                },
                content_class: ContentClass::Executable,
            },
        )
        .unwrap();
        let manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        plan_native_extension_adoption(
            &observation,
            Some(AssetId::parse("native-review").unwrap()),
            &manifest,
        )
        .unwrap()
    }
}
