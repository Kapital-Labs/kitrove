use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use kitrove_model::{AssetId, ContentHash, RemoteRevision, SnapshotDigest};

use crate::{PortableSnapshotV1, VerifiedRemoteHistory};

/// Exact head-snapshot authority for adopting one remotely distributed pack.
#[derive(Clone, Eq, PartialEq)]
pub struct PackDistributionSelection {
    pack_id: AssetId,
    target_revision: ContentHash,
    backend_revision: RemoteRevision,
    snapshot_digest: SnapshotDigest,
    snapshot: Arc<PortableSnapshotV1>,
    digest: ContentHash,
}

impl PackDistributionSelection {
    #[must_use]
    pub const fn pack_id(&self) -> &AssetId {
        &self.pack_id
    }

    #[must_use]
    pub const fn target_revision(&self) -> &ContentHash {
        &self.target_revision
    }

    #[must_use]
    pub const fn backend_revision(&self) -> &RemoteRevision {
        &self.backend_revision
    }

    #[must_use]
    pub const fn snapshot_digest(&self) -> &SnapshotDigest {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn snapshot(&self) -> &PortableSnapshotV1 {
        self.snapshot.as_ref()
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for PackDistributionSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackDistributionSelection")
            .field("snapshot_objects", &self.snapshot.objects().len())
            .finish_non_exhaustive()
    }
}

/// Selects one exact pack from the verified current head of a distribution backend.
pub fn select_pack_distribution(
    history: &VerifiedRemoteHistory,
    pack_id: &AssetId,
) -> Result<PackDistributionSelection, PackDistributionError> {
    let selected = history.snapshots().first().ok_or_else(history_invalid)?;
    let pack = selected
        .snapshot()
        .manifest()
        .packs
        .get(pack_id)
        .ok_or_else(pack_missing)?;
    let snapshot = selected.snapshot_arc();
    let snapshot_digest = snapshot.snapshot_digest().clone();
    let target_revision = pack.content_hash.clone();
    let digest = selection_digest(
        pack_id,
        &target_revision,
        selected.revision(),
        &snapshot_digest,
    );
    Ok(PackDistributionSelection {
        pack_id: pack_id.clone(),
        target_revision,
        backend_revision: selected.revision().clone(),
        snapshot_digest,
        snapshot,
        digest,
    })
}

fn selection_digest(
    pack_id: &AssetId,
    target: &ContentHash,
    backend: &RemoteRevision,
    snapshot: &SnapshotDigest,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-pack-distribution-selection-v1\0");
    for value in [
        pack_id.as_str(),
        target.as_str(),
        backend.as_str(),
        snapshot.as_str(),
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 produces a valid content hash")
}

/// Stable content-redacted distribution discovery or adoption failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PackDistributionError {
    code: &'static str,
    message: &'static str,
}

impl PackDistributionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PackDistributionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackDistributionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PackDistributionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PackDistributionError {}

pub(crate) const fn error(code: &'static str, message: &'static str) -> PackDistributionError {
    PackDistributionError { code, message }
}

const fn history_invalid() -> PackDistributionError {
    error(
        "pack_adopt.history_invalid",
        "pack adoption requires one bounded verified distribution history",
    )
}

const fn pack_missing() -> PackDistributionError {
    error(
        "pack_adopt.pack_missing",
        "the selected pack is absent from current distribution authority",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use kitrove_model::SyncLimits;

    use super::*;

    #[test]
    fn selects_only_current_verified_distribution_authority() {
        let manifest = crate::pack_creation::tests::manifest();
        let pack_id = AssetId::parse("left").unwrap();
        let expected = manifest.packs[&pack_id].content_hash.clone();
        let snapshot = Arc::new(
            PortableSnapshotV1::new(manifest, BTreeSet::new(), SyncLimits::default()).unwrap(),
        );
        let history = VerifiedRemoteHistory::new(
            vec![(RemoteRevision::parse("test:head").unwrap(), snapshot)],
            SyncLimits::default(),
        )
        .unwrap();

        let selected = select_pack_distribution(&history, &pack_id).unwrap();

        assert_eq!(selected.target_revision(), &expected);
        assert_eq!(selected.backend_revision().as_str(), "test:head");
        assert!(
            format!("{selected:?}").contains("snapshot_objects"),
            "debug output should remain structural"
        );
        assert_eq!(
            select_pack_distribution(&history, &AssetId::parse("missing").unwrap())
                .unwrap_err()
                .code(),
            "pack_adopt.pack_missing"
        );
    }
}
