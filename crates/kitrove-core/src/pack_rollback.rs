use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use kitrove_model::{AssetId, ContentHash, RemoteRevision, SnapshotDigest, SyncLimits};

use crate::PortableSnapshotV1;

/// One present snapshot and its verified backend revision.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedHistoricalSnapshot {
    revision: RemoteRevision,
    snapshot: Arc<PortableSnapshotV1>,
}

impl VerifiedHistoricalSnapshot {
    #[must_use]
    pub const fn revision(&self) -> &RemoteRevision {
        &self.revision
    }

    #[must_use]
    pub fn snapshot(&self) -> &PortableSnapshotV1 {
        self.snapshot.as_ref()
    }

    pub(crate) fn snapshot_arc(&self) -> Arc<PortableSnapshotV1> {
        Arc::clone(&self.snapshot)
    }
}

impl Debug for VerifiedHistoricalSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHistoricalSnapshot")
            .field("objects", &self.snapshot.objects().len())
            .finish_non_exhaustive()
    }
}

/// One internally verified linear remote history, ordered newest to oldest.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRemoteHistory {
    snapshots: Vec<VerifiedHistoricalSnapshot>,
}

impl VerifiedRemoteHistory {
    pub(crate) fn new(
        snapshots: Vec<(RemoteRevision, Arc<PortableSnapshotV1>)>,
        limits: SyncLimits,
    ) -> Result<Self, PackRollbackError> {
        if snapshots.is_empty() || snapshots.len() > limits.max_backend_history() {
            return Err(history_invalid());
        }
        let mut revisions = BTreeSet::new();
        for (revision, _) in &snapshots {
            if !revisions.insert(revision.as_str().to_owned()) {
                return Err(history_invalid());
            }
        }
        Ok(Self {
            snapshots: snapshots
                .into_iter()
                .map(|(revision, snapshot)| VerifiedHistoricalSnapshot { revision, snapshot })
                .collect(),
        })
    }

    #[must_use]
    pub fn snapshots(&self) -> &[VerifiedHistoricalSnapshot] {
        &self.snapshots
    }
}

impl Debug for VerifiedRemoteHistory {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRemoteHistory")
            .field("snapshots", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

/// Exact prior snapshot authority selected for one pack rollback.
#[derive(Clone, Eq, PartialEq)]
pub struct PackRollbackSelection {
    pack_id: AssetId,
    current_revision: ContentHash,
    target_revision: ContentHash,
    backend_revision: RemoteRevision,
    snapshot_digest: SnapshotDigest,
    snapshot: Arc<PortableSnapshotV1>,
    digest: ContentHash,
}

impl PackRollbackSelection {
    #[must_use]
    pub const fn pack_id(&self) -> &AssetId {
        &self.pack_id
    }

    #[must_use]
    pub const fn current_revision(&self) -> &ContentHash {
        &self.current_revision
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

impl Debug for PackRollbackSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackRollbackSelection")
            .field("snapshot_objects", &self.snapshot.objects().len())
            .finish_non_exhaustive()
    }
}

/// Selects one unambiguous exact older occurrence of a pack revision from verified ancestry.
pub fn select_pack_rollback_snapshot(
    history: &VerifiedRemoteHistory,
    pack_id: &AssetId,
    expected_current: &ContentHash,
    target_revision: &ContentHash,
) -> Result<PackRollbackSelection, PackRollbackError> {
    let current = history.snapshots.first().ok_or_else(history_invalid)?;
    let current_pack = current
        .snapshot
        .manifest()
        .packs
        .get(pack_id)
        .ok_or_else(pack_missing)?;
    if &current_pack.content_hash != expected_current {
        return Err(expected_current_mismatch());
    }
    if target_revision == expected_current {
        return Err(target_is_current());
    }
    let mut matches = history.snapshots.iter().skip(1).filter(|candidate| {
        candidate
            .snapshot
            .manifest()
            .packs
            .get(pack_id)
            .is_some_and(|pack| &pack.content_hash == target_revision)
    });
    let selected = matches.next().ok_or_else(target_missing)?;
    if matches.next().is_some() {
        return Err(target_ambiguous());
    }
    let snapshot = Arc::clone(&selected.snapshot);
    let snapshot_digest = snapshot.snapshot_digest().clone();
    let digest = selection_digest(
        pack_id,
        expected_current,
        target_revision,
        &selected.revision,
        &snapshot_digest,
    );
    Ok(PackRollbackSelection {
        pack_id: pack_id.clone(),
        current_revision: expected_current.clone(),
        target_revision: target_revision.clone(),
        backend_revision: selected.revision.clone(),
        snapshot_digest,
        snapshot,
        digest,
    })
}

fn selection_digest(
    pack_id: &AssetId,
    current: &ContentHash,
    target: &ContentHash,
    backend: &RemoteRevision,
    snapshot: &SnapshotDigest,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-pack-rollback-selection-v1\0");
    for value in [
        pack_id.as_str(),
        current.as_str(),
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

/// Stable content-redacted pack rollback selection or planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PackRollbackError {
    code: &'static str,
    message: &'static str,
}

impl PackRollbackError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PackRollbackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackRollbackError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PackRollbackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PackRollbackError {}

const fn error(code: &'static str, message: &'static str) -> PackRollbackError {
    PackRollbackError::new(code, message)
}

const fn history_invalid() -> PackRollbackError {
    error(
        "pack_rollback.history_invalid",
        "pack rollback requires one bounded verified linear snapshot history",
    )
}

const fn pack_missing() -> PackRollbackError {
    error(
        "pack_rollback.pack_missing",
        "the selected pack is absent from current remote authority",
    )
}

const fn expected_current_mismatch() -> PackRollbackError {
    error(
        "pack_rollback.expected_prior_mismatch",
        "the selected pack no longer matches --expected-prior",
    )
}

const fn target_is_current() -> PackRollbackError {
    error(
        "pack_rollback.target_is_current",
        "the rollback target must be older than current pack authority",
    )
}

const fn target_missing() -> PackRollbackError {
    error(
        "pack_rollback.target_missing",
        "the selected pack revision is absent from verified older history",
    )
}

const fn target_ambiguous() -> PackRollbackError {
    error(
        "pack_rollback.target_ambiguous",
        "the selected pack revision occurs in multiple older snapshots",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        manifest: kitrove_model::EnvironmentManifest,
        marker: &str,
    ) -> (RemoteRevision, Arc<PortableSnapshotV1>) {
        (
            RemoteRevision::parse(format!("test:{marker}")).unwrap(),
            Arc::new(
                PortableSnapshotV1::new(manifest, BTreeSet::new(), SyncLimits::default()).unwrap(),
            ),
        )
    }

    #[test]
    fn selects_one_exact_older_pack_revision_and_redacts_debug() {
        let older = crate::pack_creation::tests::manifest();
        let pack_id = AssetId::parse("left").unwrap();
        let target = older.packs[&pack_id].content_hash.clone();
        let mut current = older.clone();
        current.packs.get_mut(&pack_id).unwrap().revision =
            kitrove_model::Revision::parse("local:tooling-v2").unwrap();
        current.refresh_pack_revisions().unwrap();
        let expected = current.packs[&pack_id].content_hash.clone();
        let history = VerifiedRemoteHistory::new(
            vec![snapshot(current, "current"), snapshot(older, "older")],
            SyncLimits::default(),
        )
        .unwrap();

        let selected =
            select_pack_rollback_snapshot(&history, &pack_id, &expected, &target).unwrap();

        assert_eq!(selected.current_revision(), &expected);
        assert_eq!(selected.target_revision(), &target);
        assert_eq!(selected.backend_revision().as_str(), "test:older");
        let debug = format!("{selected:?}");
        for secret in [
            pack_id.as_str(),
            expected.as_str(),
            target.as_str(),
            selected.backend_revision().as_str(),
            selected.snapshot_digest().as_str(),
            selected.digest().as_str(),
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn duplicate_target_occurrences_are_ambiguous() {
        let target_manifest = crate::pack_creation::tests::manifest();
        let pack_id = AssetId::parse("left").unwrap();
        let target = target_manifest.packs[&pack_id].content_hash.clone();
        let mut current = target_manifest.clone();
        current.packs.get_mut(&pack_id).unwrap().revision =
            kitrove_model::Revision::parse("local:tooling-v2").unwrap();
        current.refresh_pack_revisions().unwrap();
        let expected = current.packs[&pack_id].content_hash.clone();
        let history = VerifiedRemoteHistory::new(
            vec![
                snapshot(current, "current"),
                snapshot(target_manifest.clone(), "older-a"),
                snapshot(target_manifest, "older-b"),
            ],
            SyncLimits::default(),
        )
        .unwrap();

        let error =
            select_pack_rollback_snapshot(&history, &pack_id, &expected, &target).unwrap_err();

        assert_eq!(error.code(), "pack_rollback.target_ambiguous");
    }

    #[test]
    fn stale_current_current_target_and_unknown_target_fail_closed() {
        let manifest = crate::pack_creation::tests::manifest();
        let pack_id = AssetId::parse("left").unwrap();
        let current = manifest.packs[&pack_id].content_hash.clone();
        let history = VerifiedRemoteHistory::new(
            vec![
                snapshot(manifest.clone(), "current"),
                snapshot(manifest, "older"),
            ],
            SyncLimits::default(),
        )
        .unwrap();
        assert_eq!(
            select_pack_rollback_snapshot(
                &history,
                &pack_id,
                &ContentHash::digest(b"stale"),
                &current,
            )
            .unwrap_err()
            .code(),
            "pack_rollback.expected_prior_mismatch"
        );
        assert_eq!(
            select_pack_rollback_snapshot(&history, &pack_id, &current, &current)
                .unwrap_err()
                .code(),
            "pack_rollback.target_is_current"
        );
        assert_eq!(
            select_pack_rollback_snapshot(
                &history,
                &pack_id,
                &current,
                &ContentHash::digest(b"unknown"),
            )
            .unwrap_err()
            .code(),
            "pack_rollback.target_missing"
        );
    }

    #[test]
    fn malformed_history_is_rejected_without_content_disclosure() {
        let manifest = crate::pack_creation::tests::manifest();
        let repeated = snapshot(manifest, "same");
        let error =
            VerifiedRemoteHistory::new(vec![repeated.clone(), repeated], SyncLimits::default())
                .unwrap_err();
        assert_eq!(error.code(), "pack_rollback.history_invalid");
        assert!(!format!("{error:?} {error}").contains("tooling"));
    }
}
