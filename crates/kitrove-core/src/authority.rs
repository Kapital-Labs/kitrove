use std::fmt::{self, Debug, Formatter};

use kitrove_model::{
    EnvironmentManifest, LockedAsset, LockedPack, Lockfile, ResolvedSource, Revision,
    SchemaVersion, ValidationError,
};

/// Derives the canonical environment revision from validated manifest TOML bytes.
pub fn derive_manifest_revision(
    manifest: &EnvironmentManifest,
) -> Result<Revision, ValidationError> {
    let encoded = manifest.to_toml()?;
    Revision::parse(format!(
        "manifest:blake3:{}",
        blake3::hash(encoded.as_bytes()).to_hex()
    ))
}

/// The relationship between the generated lockfile on disk and manifest authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockStatus {
    /// No lockfile was supplied.
    Missing,
    /// The supplied lockfile did not parse or validate.
    Invalid,
    /// The supplied lockfile was valid but did not equal the manifest-derived lockfile.
    Drift,
    /// The supplied lockfile exactly equals the manifest-derived lockfile.
    InSync,
}

/// A redacted lock comparison retaining the deterministic repair value.
#[derive(Clone, Eq, PartialEq)]
pub struct LockComparison {
    status: LockStatus,
    expected: Lockfile,
}

impl LockComparison {
    /// Returns the structural lock state.
    #[must_use]
    pub const fn status(&self) -> LockStatus {
        self.status
    }

    /// Returns the complete lockfile derived from manifest authority.
    #[must_use]
    pub const fn expected(&self) -> &Lockfile {
        &self.expected
    }

    /// Consumes this comparison and returns the lockfile suitable for repair.
    #[must_use]
    pub fn into_expected(self) -> Lockfile {
        self.expected
    }
}

impl Debug for LockComparison {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockComparison")
            .field("status", &self.status)
            .field("expected_assets", &self.expected.assets.len())
            .field("expected_packs", &self.expected.packs.len())
            .finish()
    }
}

/// Derives the complete generated lockfile from a validated manifest.
pub fn derive_lockfile(manifest: &EnvironmentManifest) -> Result<Lockfile, ValidationError> {
    manifest.validate()?;

    let assets = manifest
        .assets
        .iter()
        .map(|(id, asset)| {
            (
                id.clone(),
                LockedAsset {
                    id: asset.id.clone(),
                    kind: asset.kind,
                    content_hash: asset.content_hash.clone(),
                    portable_provenance: asset
                        .portable
                        .as_ref()
                        .map(|portable| portable.provenance.clone()),
                    native_provenance: asset
                        .native_variants
                        .iter()
                        .map(|(harness, variant)| (harness.clone(), variant.provenance.clone()))
                        .collect(),
                    provenance: asset.provenance.clone(),
                    compatibility: asset.compatibility.clone(),
                },
            )
        })
        .collect();

    let packs = manifest
        .packs
        .iter()
        .map(|(id, pack)| {
            (
                id.clone(),
                LockedPack {
                    id: pack.id.clone(),
                    resolved_source: ResolvedSource {
                        source: pack.source.clone(),
                        revision: pack.revision.clone(),
                        content_hash: pack.exact_source_hash.clone(),
                    },
                    content_hash: pack.content_hash.clone(),
                    members: pack.members.clone(),
                    compatibility: pack.compatibility.clone(),
                },
            )
        })
        .collect();

    let lockfile = Lockfile {
        schema_version: SchemaVersion::V1,
        assets,
        packs,
    };
    lockfile.validate()?;
    Ok(lockfile)
}

/// Compares optional lockfile text with the complete manifest-derived value.
pub fn compare_lockfile(
    manifest: &EnvironmentManifest,
    stored_json: Option<&str>,
) -> Result<LockComparison, ValidationError> {
    let expected = derive_lockfile(manifest)?;
    let status = match stored_json {
        None => LockStatus::Missing,
        Some(json) => match Lockfile::from_json(json) {
            Err(_) => LockStatus::Invalid,
            Ok(stored) if stored == expected => LockStatus::InSync,
            Ok(_) => LockStatus::Drift,
        },
    };

    Ok(LockComparison { status, expected })
}
