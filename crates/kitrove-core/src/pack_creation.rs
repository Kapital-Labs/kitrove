use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    AssetId, ComponentProvenance, ContentClass, ContentHash, EnvironmentManifest, Lockfile, Pack,
    ProvenanceId, Revision, Source,
};

use crate::{derive_lockfile, derive_manifest_revision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackMutationKind {
    Create,
    Update,
}

impl PackMutationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
        }
    }

    const fn code(self, create: &'static str, update: &'static str) -> &'static str {
        match self {
            Self::Create => create,
            Self::Update => update,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackRevisionChange {
    prior: Option<ContentHash>,
    proposed: ContentHash,
}

impl PackRevisionChange {
    #[must_use]
    pub const fn prior(&self) -> Option<&ContentHash> {
        self.prior.as_ref()
    }

    #[must_use]
    pub const fn proposed(&self) -> &ContentHash {
        &self.proposed
    }
}

/// A deterministic proposal to mutate one pack and every affected aggregate identity.
#[derive(Clone, Eq, PartialEq)]
pub struct PackMutationPlan {
    operation: PackMutationKind,
    pack: Pack,
    added_members: BTreeSet<AssetId>,
    removed_members: BTreeSet<AssetId>,
    affected_packs: BTreeMap<AssetId, PackRevisionChange>,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

/// A deterministic proposal to group existing capabilities under one pack identity.
pub type PackCreationPlan = PackMutationPlan;

/// A deterministic exact-prior proposal to update one pack identity.
pub type PackUpdatePlan = PackMutationPlan;

impl PackMutationPlan {
    #[must_use]
    pub const fn operation(&self) -> PackMutationKind {
        self.operation
    }

    #[must_use]
    pub const fn pack(&self) -> &Pack {
        &self.pack
    }

    #[must_use]
    pub const fn affected_packs(&self) -> &BTreeMap<AssetId, PackRevisionChange> {
        &self.affected_packs
    }

    #[must_use]
    pub const fn added_members(&self) -> &BTreeSet<AssetId> {
        &self.added_members
    }

    #[must_use]
    pub const fn removed_members(&self) -> &BTreeSet<AssetId> {
        &self.removed_members
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
}

impl Debug for PackMutationPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackMutationPlan")
            .field("operation", &self.operation)
            .field("pack_id", &self.pack.id)
            .field("member_count", &self.pack.members.len())
            .field("added_member_count", &self.added_members.len())
            .field("removed_member_count", &self.removed_members.len())
            .field("base_manifest_revision", &self.base_manifest_revision)
            .field(
                "proposed_manifest_revision",
                &self.proposed_manifest_revision,
            )
            .field("digest", &self.digest)
            .finish()
    }
}

/// Stable, content-redacted pack mutation failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PackMutationError {
    code: &'static str,
    message: &'static str,
}

pub type PackCreationError = PackMutationError;
pub type PackUpdateError = PackMutationError;

impl PackMutationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PackMutationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackMutationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PackMutationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PackMutationError {}

#[derive(Clone, Eq, PartialEq)]
struct SourceEvidence {
    source: Source,
    revision: Revision,
    exact_source_hash: ContentHash,
}

/// Plans a pack over existing direct members that share one exact non-harness source.
///
/// This operation groups already-captured authority. It never invents distribution provenance,
/// fetches content, or treats unrelated harness observations as one distribution.
pub fn plan_pack_creation(
    manifest: &EnvironmentManifest,
    pack_id: AssetId,
    members: BTreeSet<AssetId>,
) -> Result<PackCreationPlan, PackCreationError> {
    manifest
        .validate()
        .map_err(|_| manifest_invalid(PackMutationKind::Create))?;
    if members.is_empty() {
        return Err(error(
            "pack_create.member_required",
            "pack creation requires at least one direct member",
        ));
    }
    if manifest.assets.contains_key(&pack_id) || manifest.packs.contains_key(&pack_id) {
        return Err(error(
            "pack_create.identity_conflict",
            "the requested pack identity already exists",
        ));
    }
    if members.contains(&pack_id) {
        return Err(error(
            "pack_create.self_reference",
            "a pack cannot contain itself",
        ));
    }

    let evidence = shared_source_evidence(PackMutationKind::Create, manifest, &members)?;
    build_pack_mutation_plan(
        PackMutationKind::Create,
        manifest,
        pack_id,
        evidence,
        members,
        None,
    )
}

/// Plans an exact-prior pack replacement and re-derives every affected parent aggregate.
pub fn plan_pack_update(
    manifest: &EnvironmentManifest,
    pack_id: AssetId,
    expected_prior: ContentHash,
    members: BTreeSet<AssetId>,
) -> Result<PackUpdatePlan, PackUpdateError> {
    manifest
        .validate()
        .map_err(|_| manifest_invalid(PackMutationKind::Update))?;
    if members.is_empty() {
        return Err(error(
            "pack_update.member_required",
            "pack update requires at least one direct member",
        ));
    }
    let current_pack = manifest.packs.get(&pack_id).ok_or_else(|| {
        error(
            "pack_update.pack_missing",
            "the selected pack does not exist",
        )
    })?;
    if current_pack.content_hash != expected_prior {
        return Err(error(
            "pack_update.expected_prior_mismatch",
            "the selected pack no longer matches --expected-prior",
        ));
    }
    if members.contains(&pack_id) {
        return Err(error(
            "pack_update.self_reference",
            "a pack cannot contain itself",
        ));
    }

    let evidence = shared_source_evidence(PackMutationKind::Update, manifest, &members)?;
    build_pack_mutation_plan(
        PackMutationKind::Update,
        manifest,
        pack_id,
        evidence,
        members,
        Some(current_pack),
    )
}

fn build_pack_mutation_plan(
    operation: PackMutationKind,
    manifest: &EnvironmentManifest,
    pack_id: AssetId,
    evidence: SourceEvidence,
    members: BTreeSet<AssetId>,
    current_pack: Option<&Pack>,
) -> Result<PackMutationPlan, PackMutationError> {
    let current_members = current_pack
        .map(|pack| pack.members.keys().cloned().collect())
        .unwrap_or_default();
    let added_members = members.difference(&current_members).cloned().collect();
    let removed_members = current_members.difference(&members).cloned().collect();
    let base_manifest_revision =
        derive_manifest_revision(manifest).map_err(|_| manifest_invalid(operation))?;
    let mut proposed_manifest = manifest.clone();
    proposed_manifest.packs.insert(
        pack_id.clone(),
        pending_pack(pack_id.clone(), evidence, members),
    );
    proposed_manifest
        .refresh_pack_revisions()
        .map_err(|_| proposed_manifest_invalid(operation))?;
    let pack = proposed_manifest
        .packs
        .get(&pack_id)
        .expect("the inserted pack remains present")
        .clone();
    if current_pack.is_some_and(|current| current.content_hash == pack.content_hash) {
        return Err(error(
            "pack_update.unchanged",
            "the proposed pack update does not change aggregate authority",
        ));
    }
    let proposed_lock =
        derive_lockfile(&proposed_manifest).map_err(|_| proposed_lock_invalid(operation))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| proposed_manifest_invalid(operation))?;
    let digest = plan_digest(
        operation,
        &pack,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )?;
    let affected_packs = affected_pack_revisions(manifest, &proposed_manifest);
    Ok(PackMutationPlan {
        operation,
        pack,
        added_members,
        removed_members,
        affected_packs,
        proposed_manifest,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })
}

fn pending_pack(pack_id: AssetId, evidence: SourceEvidence, members: BTreeSet<AssetId>) -> Pack {
    Pack {
        id: pack_id,
        source: evidence.source,
        revision: evidence.revision,
        exact_source_hash: evidence.exact_source_hash,
        content_hash: ContentHash::digest(b"pending-pack-mutation"),
        members: members
            .into_iter()
            .map(|member| (member, ContentHash::digest(b"pending-pack-member")))
            .collect(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    }
}

pub(crate) fn affected_pack_revisions(
    current: &EnvironmentManifest,
    proposed: &EnvironmentManifest,
) -> BTreeMap<AssetId, PackRevisionChange> {
    proposed
        .packs
        .iter()
        .filter_map(|(id, pack)| {
            let prior = current.packs.get(id).map(|pack| &pack.content_hash);
            (prior != Some(&pack.content_hash)).then(|| {
                (
                    id.clone(),
                    PackRevisionChange {
                        prior: prior.cloned(),
                        proposed: pack.content_hash.clone(),
                    },
                )
            })
        })
        .collect()
}

fn shared_source_evidence(
    operation: PackMutationKind,
    manifest: &EnvironmentManifest,
    members: &BTreeSet<AssetId>,
) -> Result<SourceEvidence, PackCreationError> {
    let mut common: Option<BTreeMap<ProvenanceId, SourceEvidence>> = None;
    for member in members {
        let candidates = member_source_evidence(operation, manifest, member)?;
        common = Some(match common {
            None => candidates,
            Some(mut common) => {
                common.retain(|id, _| candidates.contains_key(id));
                common
            }
        });
    }
    let mut common = common.unwrap_or_default().into_values();
    let Some(evidence) = common.next() else {
        return Err(source_mismatch(operation));
    };
    if common.next().is_some() {
        Err(source_ambiguous(operation))
    } else {
        Ok(evidence)
    }
}

fn member_source_evidence(
    operation: PackMutationKind,
    manifest: &EnvironmentManifest,
    member: &AssetId,
) -> Result<BTreeMap<ProvenanceId, SourceEvidence>, PackCreationError> {
    let evidence = if let Some(asset) = manifest.assets.get(member) {
        asset
            .provenance
            .values()
            .filter_map(provenance_evidence)
            .map(|evidence| (evidence.provenance_id(), evidence))
            .collect()
    } else if let Some(pack) = manifest.packs.get(member) {
        match &pack.source {
            Source::Harness { .. } => BTreeMap::new(),
            source => {
                let evidence = SourceEvidence {
                    source: source.clone(),
                    revision: pack.revision.clone(),
                    exact_source_hash: pack.exact_source_hash.clone(),
                };
                BTreeMap::from([(evidence.provenance_id(), evidence)])
            }
        }
    } else {
        return Err(member_unknown(operation));
    };
    Ok(evidence)
}

impl SourceEvidence {
    fn provenance_id(&self) -> ProvenanceId {
        ComponentProvenance::new(
            self.source.clone(),
            self.revision.clone(),
            self.exact_source_hash.clone(),
            None,
        )
        .expect("non-harness source evidence accepts no origin scope")
        .provenance_id()
    }
}

fn provenance_evidence(provenance: &ComponentProvenance) -> Option<SourceEvidence> {
    match provenance.source() {
        Source::Harness { .. } => None,
        source => Some(SourceEvidence {
            source: source.clone(),
            revision: provenance.revision().clone(),
            exact_source_hash: provenance.exact_source_hash().clone(),
        }),
    }
}

fn plan_digest(
    operation: PackMutationKind,
    pack: &Pack,
    base_revision: &Revision,
    proposed_revision: &Revision,
    lock: &Lockfile,
) -> Result<ContentHash, PackCreationError> {
    let lock = lock
        .to_json()
        .map_err(|_| proposed_lock_invalid(operation))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(match operation {
        PackMutationKind::Create => b"kitrove-pack-creation-plan-v1\0",
        PackMutationKind::Update => b"kitrove-pack-update-plan-v1\0",
    });
    write_record(&mut hasher, pack.id.as_str());
    write_record(&mut hasher, pack.content_hash.as_str());
    write_record(&mut hasher, base_revision.as_str());
    write_record(&mut hasher, proposed_revision.as_str());
    write_record(&mut hasher, ContentHash::digest(lock.as_bytes()).as_str());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| plan_invalid(operation))
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn error(code: &'static str, message: &'static str) -> PackCreationError {
    PackMutationError { code, message }
}

const fn source_mismatch(operation: PackMutationKind) -> PackCreationError {
    error(
        operation.code("pack_create.source_mismatch", "pack_update.source_mismatch"),
        "pack members do not share one exact non-harness distribution source",
    )
}

const fn source_ambiguous(operation: PackMutationKind) -> PackCreationError {
    error(
        operation.code(
            "pack_create.source_ambiguous",
            "pack_update.source_ambiguous",
        ),
        "pack members share more than one exact distribution source",
    )
}

const fn member_unknown(operation: PackMutationKind) -> PackCreationError {
    error(
        operation.code("pack_create.member_unknown", "pack_update.member_unknown"),
        "a selected pack member does not exist",
    )
}

const fn manifest_invalid(operation: PackMutationKind) -> PackMutationError {
    match operation {
        PackMutationKind::Create => error(
            "pack_create.manifest_invalid",
            "pack creation requires a valid authoritative manifest",
        ),
        PackMutationKind::Update => error(
            "pack_update.manifest_invalid",
            "pack update requires a valid authoritative manifest",
        ),
    }
}

const fn proposed_manifest_invalid(operation: PackMutationKind) -> PackMutationError {
    match operation {
        PackMutationKind::Create => error(
            "pack_create.proposed_manifest_invalid",
            "the proposed pack does not form valid aggregate authority",
        ),
        PackMutationKind::Update => error(
            "pack_update.proposed_manifest_invalid",
            "the proposed update does not form valid aggregate authority",
        ),
    }
}

const fn proposed_lock_invalid(operation: PackMutationKind) -> PackCreationError {
    error(
        operation.code(
            "pack_create.proposed_lock_invalid",
            "pack_update.proposed_lock_invalid",
        ),
        "the generated pack lock authority is invalid",
    )
}

const fn plan_invalid(operation: PackMutationKind) -> PackCreationError {
    match operation {
        PackMutationKind::Create => error(
            "pack_create.plan_invalid",
            "the pack creation plan identity is invalid",
        ),
        PackMutationKind::Update => error(
            "pack_update.plan_invalid",
            "the pack update plan identity is invalid",
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{plan_pack_creation, plan_pack_update};
    use kitrove_model::{
        Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Pack,
        PortablePath, Revision, SchemaVersion, Source,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn asset(id: &str) -> Asset {
        let mut asset = Asset {
            id: AssetId::parse(id).unwrap(),
            kind: AssetKind::Skill,
            content_hash: ContentHash::digest(b"pending-pack-create-asset"),
            provenance: BTreeMap::new(),
            portable: None,
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        asset
    }

    fn source() -> Source {
        Source::Local {
            path: PortablePath::parse("distributions/tooling").unwrap(),
        }
    }

    fn pack(id: &str, member: &str, marker: &[u8]) -> Pack {
        Pack {
            id: AssetId::parse(id).unwrap(),
            source: source(),
            revision: Revision::parse("local:tooling-v1").unwrap(),
            exact_source_hash: ContentHash::digest(b"tooling-distribution-v1"),
            content_hash: ContentHash::digest(marker),
            members: BTreeMap::from([(
                AssetId::parse(member).unwrap(),
                ContentHash::digest(b"pending-pack-create-member"),
            )]),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        }
    }

    pub(crate) fn manifest() -> EnvironmentManifest {
        let alpha = asset("alpha");
        let beta = asset("beta");
        let left = pack("left", "alpha", b"pending-left");
        let right = pack("right", "beta", b"pending-right");
        let mut manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::from([(alpha.id.clone(), alpha), (beta.id.clone(), beta)]),
            packs: BTreeMap::from([(left.id.clone(), left), (right.id.clone(), right)]),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        manifest.refresh_pack_revisions().unwrap();
        manifest
    }

    #[test]
    fn derives_aggregate_authority_from_one_shared_exact_source() {
        let manifest = manifest();
        let plan = plan_pack_creation(
            &manifest,
            AssetId::parse("tooling").unwrap(),
            [
                AssetId::parse("right").unwrap(),
                AssetId::parse("left").unwrap(),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();

        assert_eq!(plan.pack().source, source());
        assert_eq!(plan.pack().members.len(), 2);
        assert_eq!(
            plan.proposed_manifest().packs[&AssetId::parse("tooling").unwrap()],
            *plan.pack()
        );
        plan.proposed_manifest().validate().unwrap();
        assert_eq!(
            plan.proposed_lock().packs[&AssetId::parse("tooling").unwrap()].content_hash,
            plan.pack().content_hash
        );
    }

    #[test]
    fn refuses_unknown_conflicting_and_mixed_source_members() {
        let manifest = manifest();
        let unknown = plan_pack_creation(
            &manifest,
            AssetId::parse("tooling").unwrap(),
            [AssetId::parse("missing").unwrap()].into_iter().collect(),
        )
        .unwrap_err();
        assert_eq!(unknown.code(), "pack_create.member_unknown");

        let conflict = plan_pack_creation(
            &manifest,
            AssetId::parse("left").unwrap(),
            [AssetId::parse("right").unwrap()].into_iter().collect(),
        )
        .unwrap_err();
        assert_eq!(conflict.code(), "pack_create.identity_conflict");

        let mut mixed = manifest;
        mixed
            .packs
            .get_mut(&AssetId::parse("right").unwrap())
            .unwrap()
            .exact_source_hash = ContentHash::digest(b"other-distribution");
        mixed.refresh_pack_revisions().unwrap();
        let mismatch = plan_pack_creation(
            &mixed,
            AssetId::parse("tooling").unwrap(),
            [
                AssetId::parse("left").unwrap(),
                AssetId::parse("right").unwrap(),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap_err();
        assert_eq!(mismatch.code(), "pack_create.source_mismatch");
    }

    #[test]
    fn debug_output_omits_source_authority() {
        let plan = plan_pack_creation(
            &manifest(),
            AssetId::parse("tooling").unwrap(),
            [AssetId::parse("left").unwrap()].into_iter().collect(),
        )
        .unwrap();
        let debug = format!("{plan:?}");
        assert!(debug.contains("member_count"));
        assert!(!debug.contains("distributions/tooling"));
        assert!(!debug.contains(plan.pack().exact_source_hash.as_str()));
    }

    #[test]
    fn exact_prior_update_rederives_every_affected_parent_pack() {
        let created = plan_pack_creation(
            &manifest(),
            AssetId::parse("tooling").unwrap(),
            BTreeSet::from([
                AssetId::parse("left").unwrap(),
                AssetId::parse("right").unwrap(),
            ]),
        )
        .unwrap();
        let manifest = created.proposed_manifest();
        let left = AssetId::parse("left").unwrap();
        let tooling = AssetId::parse("tooling").unwrap();
        let expected_prior = manifest.packs[&left].content_hash.clone();

        let plan = plan_pack_update(
            manifest,
            left.clone(),
            expected_prior.clone(),
            BTreeSet::from([AssetId::parse("right").unwrap()]),
        )
        .unwrap();

        assert_eq!(plan.affected_packs().len(), 2);
        assert_eq!(plan.affected_packs()[&left].prior(), Some(&expected_prior));
        assert!(plan.affected_packs().contains_key(&tooling));
        assert_eq!(
            plan.added_members()
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["right"]
        );
        assert_eq!(
            plan.removed_members()
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["alpha"]
        );
        assert_eq!(plan.pack(), &plan.proposed_manifest().packs[&left]);
        plan.proposed_manifest().validate().unwrap();

        let stale = plan_pack_update(
            manifest,
            left,
            ContentHash::digest(b"stale-pack-revision"),
            BTreeSet::from([AssetId::parse("right").unwrap()]),
        )
        .unwrap_err();
        assert_eq!(stale.code(), "pack_update.expected_prior_mismatch");
    }
}
