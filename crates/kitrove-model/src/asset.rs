use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AssetId, BindingName, ContentClass, ContentHash, FidelityResult, HarnessId, PortablePath,
    ProvenanceId, RepositoryUrl, Revision, ValidationError,
};

/// The durable capability class represented by an asset.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Skill,
    Instruction,
    Agent,
    Command,
    Hook,
    Mcp,
    Plugin,
    Extension,
    Pack,
}

/// A moving, harness-neutral declaration of where content originates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Harness {
        harness: HarnessId,
        origin: PortablePath,
    },
    Local {
        path: PortablePath,
    },
    Git {
        repository: RepositoryUrl,
        subdirectory: Option<PortablePath>,
    },
}

/// The immutable resolution of a declared source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSource {
    pub source: Source,
    pub revision: Revision,
    pub content_hash: ContentHash,
}

/// Immutable source evidence shared by one or more authored asset components.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComponentProvenance {
    source: Source,
    revision: Revision,
    exact_source_hash: ContentHash,
    origin_scope: Option<crate::HarnessScope>,
}

impl ComponentProvenance {
    /// Constructs provenance while enforcing the harness-origin scope boundary.
    pub fn new(
        source: Source,
        revision: Revision,
        exact_source_hash: ContentHash,
        origin_scope: Option<crate::HarnessScope>,
    ) -> Result<Self, ValidationError> {
        match (&source, origin_scope) {
            (Source::Harness { .. }, None) => {
                return Err(ValidationError::new(
                    "provenance.origin_scope_required",
                    "harness provenance requires an origin scope",
                ));
            }
            (Source::Local { .. } | Source::Git { .. }, Some(_)) => {
                return Err(ValidationError::new(
                    "provenance.origin_scope_unexpected",
                    "non-harness provenance cannot declare an origin scope",
                ));
            }
            _ => {}
        }
        Ok(Self {
            source,
            revision,
            exact_source_hash,
            origin_scope,
        })
    }

    /// Returns the moving source declaration captured by this record.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// Returns the immutable source or observation revision.
    #[must_use]
    pub fn revision(&self) -> &Revision {
        &self.revision
    }

    /// Returns the exact hash captured before portable projection.
    #[must_use]
    pub fn exact_source_hash(&self) -> &ContentHash {
        &self.exact_source_hash
    }

    /// Returns the origin scope for harness observations.
    #[must_use]
    pub fn origin_scope(&self) -> Option<crate::HarnessScope> {
        self.origin_scope
    }

    /// Computes the version-1 identity over the complete provenance record.
    #[must_use]
    pub fn provenance_id(&self) -> ProvenanceId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-component-provenance-v1\0");
        hash_source(&mut hasher, &self.source);
        write_text_record(&mut hasher, self.revision.as_str());
        write_text_record(&mut hasher, self.exact_source_hash.as_str());
        match self.origin_scope {
            Some(scope) => {
                hasher.update(&[1]);
                write_text_record(&mut hasher, scope.as_str());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        ProvenanceId::parse(format!("provenance:blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid ProvenanceId")
    }
}

impl<'de> Deserialize<'de> for ComponentProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedProvenance {
            source: Source,
            revision: Revision,
            exact_source_hash: ContentHash,
            origin_scope: Option<crate::HarnessScope>,
        }

        let value = PersistedProvenance::deserialize(deserializer)?;
        Self::new(
            value.source,
            value.revision,
            value.exact_source_hash,
            value.origin_scope,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// A portable core stored in Kitrove's object namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableContent {
    pub format: String,
    pub root: PortablePath,
    pub object_hash: ContentHash,
    pub provenance: ProvenanceId,
}

/// Harness-specific content preserved without normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeVariant {
    pub harness: HarnessId,
    pub format: String,
    pub root: PortablePath,
    pub object_hash: ContentHash,
    pub content_class: ContentClass,
    pub provenance: ProvenanceId,
}

/// A harness-neutral capability asset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub id: AssetId,
    pub kind: AssetKind,
    pub content_hash: ContentHash,
    #[serde(default)]
    pub provenance: BTreeMap<ProvenanceId, ComponentProvenance>,
    pub portable: Option<PortableContent>,
    #[serde(default)]
    pub native_variants: BTreeMap<HarnessId, NativeVariant>,
    #[serde(default)]
    pub compatibility: BTreeMap<HarnessId, FidelityResult>,
    pub content_class: ContentClass,
    #[serde(default)]
    pub required_bindings: BTreeSet<BindingName>,
}

impl Asset {
    /// Computes the complete version-2 asset revision identity, excluding the stored hash itself.
    #[must_use]
    pub fn expected_content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-asset-revision-v3\0");
        write_text_record(&mut hasher, self.id.as_str());
        hasher.update(&[asset_kind_tag(self.kind)]);

        write_count(&mut hasher, self.provenance.len());
        for (id, record) in &self.provenance {
            write_text_record(&mut hasher, id.as_str());
            write_text_record(&mut hasher, record.provenance_id().as_str());
        }

        match &self.portable {
            Some(portable) => {
                hasher.update(&[1]);
                write_text_record(&mut hasher, &portable.format);
                write_text_record(&mut hasher, portable.root.as_str());
                write_text_record(&mut hasher, portable.object_hash.as_str());
                write_text_record(&mut hasher, portable.provenance.as_str());
            }
            None => {
                hasher.update(&[0]);
            }
        }

        write_count(&mut hasher, self.native_variants.len());
        for (harness, variant) in &self.native_variants {
            write_text_record(&mut hasher, harness.as_str());
            write_text_record(&mut hasher, variant.harness.as_str());
            write_text_record(&mut hasher, &variant.format);
            write_text_record(&mut hasher, variant.root.as_str());
            write_text_record(&mut hasher, variant.object_hash.as_str());
            hasher.update(&[content_class_tag(variant.content_class)]);
            write_text_record(&mut hasher, variant.provenance.as_str());
        }

        write_count(&mut hasher, self.compatibility.len());
        for (harness, result) in &self.compatibility {
            write_text_record(&mut hasher, harness.as_str());
            hash_fidelity(&mut hasher, result);
        }

        hasher.update(&[content_class_tag(self.content_class)]);
        write_count(&mut hasher, self.required_bindings.len());
        for binding in &self.required_bindings {
            write_text_record(&mut hasher, binding.as_str());
        }

        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid ContentHash")
    }

    /// Replaces the stored revision identity with the value derived from the complete asset.
    pub fn refresh_content_hash(&mut self) {
        self.content_hash = self.expected_content_hash();
    }
}

fn hash_source(hasher: &mut blake3::Hasher, source: &Source) {
    match source {
        Source::Harness { harness, origin } => {
            hasher.update(&[0]);
            write_text_record(hasher, harness.as_str());
            write_text_record(hasher, origin.as_str());
        }
        Source::Local { path } => {
            hasher.update(&[1]);
            write_text_record(hasher, path.as_str());
        }
        Source::Git {
            repository,
            subdirectory,
        } => {
            hasher.update(&[2]);
            write_text_record(hasher, repository.as_str());
            write_optional_text(hasher, subdirectory.as_ref().map(PortablePath::as_str));
        }
    }
}

fn hash_fidelity(hasher: &mut blake3::Hasher, result: &FidelityResult) {
    hasher.update(&[match result.fidelity() {
        crate::Fidelity::Native => 0,
        crate::Fidelity::Portable => 1,
        crate::Fidelity::Adapted => 2,
        crate::Fidelity::Partial => 3,
        crate::Fidelity::Unsupported => 4,
        crate::Fidelity::Blocked => 5,
    }]);
    write_count(hasher, result.reasons().len());
    for reason in result.reasons() {
        write_text_record(hasher, &reason.code);
        write_text_record(hasher, &reason.message);
    }
    write_count(hasher, result.evidence().len());
    for evidence in result.evidence() {
        write_text_record(hasher, &evidence.kind);
        write_text_record(hasher, &evidence.detail);
    }
    write_count(hasher, result.blocked_requirements().len());
    for requirement in result.blocked_requirements() {
        match requirement {
            crate::BlockedRequirement::Binding { name } => {
                hasher.update(&[0]);
                write_text_record(hasher, name.as_str());
            }
            crate::BlockedRequirement::ExecutableTrust => {
                hasher.update(&[1]);
            }
        }
    }
    write_text_record(hasher, result.adapter_version());
    write_optional_text(hasher, result.harness_version());
}

fn write_optional_text(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            write_text_record(hasher, value);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn write_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_be_bytes());
}

fn write_text_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn asset_kind_tag(kind: AssetKind) -> u8 {
    match kind {
        AssetKind::Skill => 0,
        AssetKind::Instruction => 1,
        AssetKind::Agent => 2,
        AssetKind::Command => 3,
        AssetKind::Hook => 4,
        AssetKind::Mcp => 5,
        AssetKind::Plugin => 6,
        AssetKind::Extension => 7,
        AssetKind::Pack => 8,
    }
}

const fn content_class_tag(class: ContentClass) -> u8 {
    match class {
        ContentClass::DataOnly => 0,
        ContentClass::AgentActive => 1,
        ContentClass::Executable => 2,
    }
}

/// An aggregate lifecycle object retaining one pack identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub id: AssetId,
    pub source: Source,
    pub revision: Revision,
    pub exact_source_hash: ContentHash,
    pub content_hash: ContentHash,
    pub members: BTreeMap<AssetId, ContentHash>,
    #[serde(default)]
    pub compatibility: BTreeMap<HarnessId, FidelityResult>,
    pub content_class: ContentClass,
    #[serde(default)]
    pub required_bindings: BTreeSet<BindingName>,
}

impl Pack {
    /// Computes the complete version-1 aggregate pack revision.
    #[must_use]
    pub fn expected_content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-pack-revision-v1\0");
        write_text_record(&mut hasher, self.id.as_str());
        hash_source(&mut hasher, &self.source);
        write_text_record(&mut hasher, self.revision.as_str());
        write_text_record(&mut hasher, self.exact_source_hash.as_str());

        write_count(&mut hasher, self.members.len());
        for (id, revision) in &self.members {
            write_text_record(&mut hasher, id.as_str());
            write_text_record(&mut hasher, revision.as_str());
        }

        write_count(&mut hasher, self.compatibility.len());
        for (harness, result) in &self.compatibility {
            write_text_record(&mut hasher, harness.as_str());
            hash_fidelity(&mut hasher, result);
        }

        hasher.update(&[content_class_tag(self.content_class)]);
        write_count(&mut hasher, self.required_bindings.len());
        for binding in &self.required_bindings {
            write_text_record(&mut hasher, binding.as_str());
        }

        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid ContentHash")
    }

    /// Replaces the stored revision identity with the value derived from the complete pack.
    pub fn refresh_content_hash(&mut self) {
        self.content_hash = self.expected_content_hash();
    }
}

/// One resolved asset record in the deterministic lockfile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedAsset {
    pub id: AssetId,
    pub kind: AssetKind,
    pub content_hash: ContentHash,
    pub portable_provenance: Option<ProvenanceId>,
    #[serde(default)]
    pub native_provenance: BTreeMap<HarnessId, ProvenanceId>,
    #[serde(default)]
    pub provenance: BTreeMap<ProvenanceId, ComponentProvenance>,
    #[serde(default)]
    pub compatibility: BTreeMap<HarnessId, FidelityResult>,
}

/// One resolved first-class pack record in the deterministic lockfile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPack {
    pub id: AssetId,
    pub resolved_source: ResolvedSource,
    pub content_hash: ContentHash,
    pub members: BTreeMap<AssetId, ContentHash>,
    #[serde(default)]
    pub compatibility: BTreeMap<HarnessId, FidelityResult>,
}
