use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    ContentHash, PortablePath, PublicationId, RemoteKey, RemoteRevision, SyncBaseRecord, SyncLimits,
};
use serde::{Deserialize, Serialize};

use crate::{PublicationIntent, SyncPlan};

/// Durable synchronization transaction phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncJournalPhase {
    Prepared,
    Publishing,
    RemotePublished,
    LocalCommitting,
    LocalCommitted,
    BaseCommitting,
    BaseCommitted,
    Complete,
}

/// Exact durable evidence for one confirmed synchronization transaction.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncJournal {
    schema_version: u32,
    phase: SyncJournalPhase,
    plan_digest: ContentHash,
    remote_key: RemoteKey,
    publication_id: Option<PublicationId>,
    prior_remote_revision: RemoteRevision,
    publication_intent: Option<String>,
    proposed_remote_revision: RemoteRevision,
    local_snapshot_digest: kitrove_model::SnapshotDigest,
    merged_snapshot_digest: kitrove_model::SnapshotDigest,
    old_manifest_hash: ContentHash,
    old_lock_hash: ContentHash,
    new_manifest_hash: ContentHash,
    new_lock_hash: ContentHash,
    prior_base_generation: Option<ContentHash>,
    proposed_base_generation: ContentHash,
    staging_snapshot: PortablePath,
    staging_manifest: PortablePath,
    staging_lock: PortablePath,
    staging_base: PortablePath,
}

impl SyncJournal {
    /// Constructs the only valid prepared journal for one exact confirmed plan.
    pub fn prepared(
        plan: &SyncPlan,
        remote_key: RemoteKey,
        publication: Option<(PublicationId, &PublicationIntent)>,
        prior_base_generation: Option<ContentHash>,
        limits: SyncLimits,
    ) -> Result<Self, SyncJournalError> {
        let publication_required = plan
            .remote_snapshot()
            .is_none_or(|remote| remote.snapshot_digest() != plan.merged().snapshot_digest());
        if publication_required != publication.is_some() {
            return Err(invalid());
        }
        let proposed_remote_revision = publication.as_ref().map_or_else(
            || plan.remote_revision().clone(),
            |(_, intent)| intent.proposed_revision().clone(),
        );
        if publication_required && &proposed_remote_revision == plan.remote_revision() {
            return Err(invalid());
        }
        let base = SyncBaseRecord::new(
            remote_key.clone(),
            plan.merged().snapshot_digest().clone(),
            plan.merged().manifest_revision().clone(),
            proposed_remote_revision.clone(),
            plan.merged().objects().clone(),
            limits,
        )
        .map_err(|_| invalid())?;
        let base_json = base.to_json(limits).map_err(|_| invalid())?;
        let proposed_base_generation =
            framed_hash(b"kitrove-sync-base-generation-v1\0", &base_json);
        let prefix = staging_prefix(&remote_key, plan.digest())?;
        let journal = Self {
            schema_version: 1,
            phase: SyncJournalPhase::Prepared,
            plan_digest: plan.digest().clone(),
            remote_key,
            publication_id: publication.as_ref().map(|(id, _)| id.clone()),
            prior_remote_revision: plan.remote_revision().clone(),
            publication_intent: publication.map(|(_, intent)| intent.as_persisted().to_owned()),
            proposed_remote_revision,
            local_snapshot_digest: plan.local().snapshot_digest().clone(),
            merged_snapshot_digest: plan.merged().snapshot_digest().clone(),
            old_manifest_hash: ContentHash::digest(plan.local().manifest_toml().as_bytes()),
            old_lock_hash: ContentHash::digest(plan.local().lock_json().as_bytes()),
            new_manifest_hash: ContentHash::digest(plan.merged().manifest_toml().as_bytes()),
            new_lock_hash: ContentHash::digest(plan.merged().lock_json().as_bytes()),
            prior_base_generation,
            proposed_base_generation,
            staging_snapshot: joined(&prefix, "snapshot.json")?,
            staging_manifest: joined(&prefix, "manifest.toml")?,
            staging_lock: joined(&prefix, "lock.json")?,
            staging_base: joined(&prefix, "base")?,
        };
        journal.validate(limits)?;
        Ok(journal)
    }

    /// Parses strict canonical journal JSON and reconstructs its bounded opaque intent.
    pub fn from_json(input: &str, limits: SyncLimits) -> Result<Self, SyncJournalError> {
        if input.len() as u64 > limits.max_control_bytes() {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Persisted {
            schema_version: u32,
            phase: SyncJournalPhase,
            plan_digest: ContentHash,
            remote_key: RemoteKey,
            publication_id: Option<PublicationId>,
            prior_remote_revision: RemoteRevision,
            publication_intent: Option<String>,
            proposed_remote_revision: RemoteRevision,
            local_snapshot_digest: kitrove_model::SnapshotDigest,
            merged_snapshot_digest: kitrove_model::SnapshotDigest,
            old_manifest_hash: ContentHash,
            old_lock_hash: ContentHash,
            new_manifest_hash: ContentHash,
            new_lock_hash: ContentHash,
            prior_base_generation: Option<ContentHash>,
            proposed_base_generation: ContentHash,
            staging_snapshot: PortablePath,
            staging_manifest: PortablePath,
            staging_lock: PortablePath,
            staging_base: PortablePath,
        }
        let value: Persisted = serde_json::from_str(input).map_err(|_| invalid())?;
        let journal = Self {
            schema_version: value.schema_version,
            phase: value.phase,
            plan_digest: value.plan_digest,
            remote_key: value.remote_key,
            publication_id: value.publication_id,
            prior_remote_revision: value.prior_remote_revision,
            publication_intent: value.publication_intent,
            proposed_remote_revision: value.proposed_remote_revision,
            local_snapshot_digest: value.local_snapshot_digest,
            merged_snapshot_digest: value.merged_snapshot_digest,
            old_manifest_hash: value.old_manifest_hash,
            old_lock_hash: value.old_lock_hash,
            new_manifest_hash: value.new_manifest_hash,
            new_lock_hash: value.new_lock_hash,
            prior_base_generation: value.prior_base_generation,
            proposed_base_generation: value.proposed_base_generation,
            staging_snapshot: value.staging_snapshot,
            staging_manifest: value.staging_manifest,
            staging_lock: value.staging_lock,
            staging_base: value.staging_base,
        };
        journal.validate(limits)?;
        if journal.to_json(limits)? != input {
            return Err(invalid());
        }
        Ok(journal)
    }

    /// Serializes the validated journal deterministically.
    pub fn to_json(&self, limits: SyncLimits) -> Result<String, SyncJournalError> {
        self.validate(limits)?;
        let mut encoded = serde_json::to_string_pretty(self).map_err(|_| invalid())?;
        encoded.push('\n');
        if encoded.len() as u64 > limits.max_control_bytes() {
            return Err(invalid());
        }
        Ok(encoded)
    }

    /// Advances exactly one durable phase without changing bound evidence.
    pub fn advance(&self, next: SyncJournalPhase) -> Result<Self, SyncJournalError> {
        let valid = if self.phase == SyncJournalPhase::Prepared {
            match self.publication_intent {
                Some(_) => next == SyncJournalPhase::Publishing,
                None => next == SyncJournalPhase::RemotePublished,
            }
        } else {
            next as u8 == self.phase as u8 + 1
        };
        if !valid {
            return Err(transition_invalid());
        }
        let mut journal = self.clone();
        journal.phase = next;
        Ok(journal)
    }

    #[must_use]
    pub const fn phase(&self) -> SyncJournalPhase {
        self.phase
    }

    #[must_use]
    pub const fn plan_digest(&self) -> &ContentHash {
        &self.plan_digest
    }

    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }

    #[must_use]
    pub const fn publication_id(&self) -> Option<&PublicationId> {
        self.publication_id.as_ref()
    }

    #[must_use]
    pub const fn prior_remote_revision(&self) -> &RemoteRevision {
        &self.prior_remote_revision
    }

    #[must_use]
    pub const fn proposed_remote_revision(&self) -> &RemoteRevision {
        &self.proposed_remote_revision
    }

    #[must_use]
    pub const fn local_snapshot_digest(&self) -> &kitrove_model::SnapshotDigest {
        &self.local_snapshot_digest
    }

    #[must_use]
    pub const fn merged_snapshot_digest(&self) -> &kitrove_model::SnapshotDigest {
        &self.merged_snapshot_digest
    }

    #[must_use]
    pub const fn prior_base_generation(&self) -> Option<&ContentHash> {
        self.prior_base_generation.as_ref()
    }

    #[must_use]
    pub const fn proposed_base_generation(&self) -> &ContentHash {
        &self.proposed_base_generation
    }

    #[must_use]
    pub const fn staging_snapshot(&self) -> &PortablePath {
        &self.staging_snapshot
    }

    #[must_use]
    pub const fn staging_manifest(&self) -> &PortablePath {
        &self.staging_manifest
    }

    #[must_use]
    pub const fn staging_lock(&self) -> &PortablePath {
        &self.staging_lock
    }

    #[must_use]
    pub const fn staging_base(&self) -> &PortablePath {
        &self.staging_base
    }

    /// Reconstructs the exact backend-owned intent after journal validation.
    pub fn publication_intent(
        &self,
        limits: SyncLimits,
    ) -> Result<Option<PublicationIntent>, SyncJournalError> {
        self.publication_intent
            .as_ref()
            .map(|encoded| {
                PublicationIntent::from_persisted(
                    encoded.clone(),
                    self.proposed_remote_revision.clone(),
                    limits,
                )
                .map_err(|_| invalid())
            })
            .transpose()
    }

    fn validate(&self, limits: SyncLimits) -> Result<(), SyncJournalError> {
        if self.schema_version != 1 {
            return Err(invalid());
        }
        self.publication_intent(limits)?;
        if self.publication_id.is_some() != self.publication_intent.is_some() {
            return Err(invalid());
        }
        let prefix = staging_prefix(&self.remote_key, &self.plan_digest)?;
        if self.staging_snapshot != joined(&prefix, "snapshot.json")?
            || self.staging_manifest != joined(&prefix, "manifest.toml")?
            || self.staging_lock != joined(&prefix, "lock.json")?
            || self.staging_base != joined(&prefix, "base")?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Debug for SyncJournal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncJournal")
            .field("phase", &self.phase)
            .field("plan_digest", &self.plan_digest)
            .finish_non_exhaustive()
    }
}

/// Stable redacted journal validation failure.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncJournalError {
    code: &'static str,
    message: &'static str,
}

impl SyncJournalError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl Debug for SyncJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncJournalError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SyncJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SyncJournalError {}

fn staging_prefix(
    remote: &RemoteKey,
    plan: &ContentHash,
) -> Result<PortablePath, SyncJournalError> {
    let remote = remote.as_str().rsplit(':').next().ok_or_else(invalid)?;
    let plan = plan.as_str().rsplit(':').next().ok_or_else(invalid)?;
    PortablePath::parse(format!("sync/{remote}/staging/{plan}")).map_err(|_| invalid())
}

fn joined(prefix: &PortablePath, suffix: &str) -> Result<PortablePath, SyncJournalError> {
    PortablePath::parse(format!("{}/{suffix}", prefix.as_str())).map_err(|_| invalid())
}

fn framed_hash(frame: &[u8], value: &str) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(frame);
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 produces a valid content hash")
}

const fn invalid() -> SyncJournalError {
    SyncJournalError {
        code: "sync.journal_invalid",
        message: "synchronization journal evidence is invalid",
    }
}

const fn transition_invalid() -> SyncJournalError {
    SyncJournalError {
        code: "sync.journal_transition_invalid",
        message: "synchronization journal phase transition is invalid",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use kitrove_model::{ObjectDescriptor, SnapshotObjectKind};

    use super::*;
    use crate::adoption::tests::{capabilities, empty_manifest};
    use crate::{
        PortableSnapshotV1, RemoteSnapshot, SyncPlanOutcome, VerifiedSkillObjectCatalog, plan_sync,
    };

    fn snapshot(manifest: kitrove_model::EnvironmentManifest) -> PortableSnapshotV1 {
        let mut objects = BTreeSet::new();
        for asset in manifest.assets.values() {
            if let Some(portable) = &asset.portable {
                objects.insert(
                    ObjectDescriptor::new(
                        SnapshotObjectKind::PortableSkillTree,
                        portable.root.clone(),
                        portable.object_hash.clone(),
                        1,
                    )
                    .unwrap(),
                );
            }
            for native in asset.native_variants.values() {
                objects.insert(
                    ObjectDescriptor::new(
                        SnapshotObjectKind::NativeSkillObject,
                        native.root.clone(),
                        native.object_hash.clone(),
                        1,
                    )
                    .unwrap(),
                );
            }
        }
        PortableSnapshotV1::new(manifest, objects, SyncLimits::default()).unwrap()
    }

    fn ready_plan(local: PortableSnapshotV1, remote: RemoteSnapshot) -> Box<SyncPlan> {
        let catalog = VerifiedSkillObjectCatalog::new([], []).unwrap();
        let SyncPlanOutcome::Ready(plan) = plan_sync(
            local,
            None,
            remote,
            &catalog,
            &capabilities(),
            SyncLimits::default(),
        )
        .unwrap() else {
            panic!("fixture must be ready");
        };
        plan
    }

    fn remote_key() -> RemoteKey {
        RemoteKey::parse(format!("remote:blake3:{}", "a".repeat(64))).unwrap()
    }

    #[test]
    fn no_publish_journal_round_trips_and_skips_to_remote_published() {
        let limits = SyncLimits::default();
        let empty = snapshot(empty_manifest());
        let plan = ready_plan(
            empty.clone(),
            RemoteSnapshot::present(RemoteRevision::parse("remote-1").unwrap(), empty),
        );
        let journal = SyncJournal::prepared(&plan, remote_key(), None, None, limits).unwrap();
        let encoded = journal.to_json(limits).unwrap();

        assert_eq!(SyncJournal::from_json(&encoded, limits).unwrap(), journal);
        assert!(journal.publication_intent(limits).unwrap().is_none());
        assert_eq!(
            journal
                .advance(SyncJournalPhase::RemotePublished)
                .unwrap()
                .phase(),
            SyncJournalPhase::RemotePublished
        );
        assert_eq!(
            journal
                .advance(SyncJournalPhase::Publishing)
                .unwrap_err()
                .code(),
            "sync.journal_transition_invalid"
        );
    }

    #[test]
    fn publishing_journal_binds_intent_and_digest_scoped_paths_without_debug_leakage() {
        let limits = SyncLimits::default();
        let mut populated = empty_manifest();
        populated.required_bindings =
            BTreeSet::from([kitrove_model::BindingName::parse("review").unwrap()]);
        let local = snapshot(populated);
        let plan = ready_plan(
            local,
            RemoteSnapshot::absent(RemoteRevision::parse("prior-revision-canary").unwrap()),
        );
        let intent_canary = "PUBLICATION-INTENT-CANARY";
        let proposed = RemoteRevision::parse("proposed-revision-canary").unwrap();
        let intent =
            PublicationIntent::from_persisted(intent_canary.to_owned(), proposed, limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap();
        let journal = SyncJournal::prepared(
            &plan,
            remote_key(),
            Some((publication, &intent)),
            None,
            limits,
        )
        .unwrap();
        let encoded = journal.to_json(limits).unwrap();

        assert!(encoded.contains(intent_canary));
        assert!(!format!("{journal:?}").contains(intent_canary));
        assert_eq!(
            journal
                .advance(SyncJournalPhase::Publishing)
                .unwrap()
                .phase(),
            SyncJournalPhase::Publishing
        );

        let mut forged: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        forged["staging_manifest"] = serde_json::Value::String("elsewhere".to_owned());
        let mut forged = serde_json::to_string_pretty(&forged).unwrap();
        forged.push('\n');
        assert_eq!(
            SyncJournal::from_json(&forged, limits).unwrap_err().code(),
            "sync.journal_invalid"
        );
    }
}
