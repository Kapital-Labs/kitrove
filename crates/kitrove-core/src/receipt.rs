use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use kitrove_adapter_api::{
    AdapterError, AdapterResult, FindingSeverity, FindingSubject, ScanFinding,
};
use kitrove_model::{
    BindingName, BindingResolver, ContentHash, DeploymentReceipt, HarnessId, HarnessScope,
    MachineConfig, NormalizedDestination, ReceiptId, ReceiptTarget, ScanRecord, SchemaVersion,
    TrustDecision,
};
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserialize, Deserializer as _};
use serde_json::value::RawValue;

const DEFAULT_MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_RECEIPTS: usize = 4_096;
const DEFAULT_MAX_RECEIPT_BYTES: usize = 1024 * 1024;

/// Namespace for the strict, read-only local-state diagnostic reader.
pub struct ReceiptIndex;

/// One receipt whose persisted shape and identity are valid in isolation.
#[derive(Clone, Eq, PartialEq)]
pub struct InspectedReceipt {
    pub receipt_id: ReceiptId,
    pub receipt: DeploymentReceipt,
}

impl Debug for InspectedReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectedReceipt")
            .field("receipt_id", &self.receipt_id)
            .field("harness", &self.receipt.harness)
            .field("scope", &self.receipt.scope)
            .finish_non_exhaustive()
    }
}

/// Smallest safe ownership partition recoverable from one malformed receipt.
#[derive(Clone, Eq, PartialEq)]
pub enum ReceiptInvalidityScope {
    Destination {
        harness: HarnessId,
        scope: HarnessScope,
        normalized_destination: NormalizedDestination,
    },
    HarnessScope {
        harness: HarnessId,
        scope: HarnessScope,
    },
    Harness(HarnessId),
    Report,
}

impl Debug for ReceiptInvalidityScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Destination { harness, scope, .. } => formatter
                .debug_struct("Destination")
                .field("harness", harness)
                .field("scope", scope)
                .finish_non_exhaustive(),
            Self::HarnessScope { harness, scope } => formatter
                .debug_struct("HarnessScope")
                .field("harness", harness)
                .field("scope", scope)
                .finish(),
            Self::Harness(harness) => formatter.debug_tuple("Harness").field(harness).finish(),
            Self::Report => formatter.write_str("Report"),
        }
    }
}

/// One receipt record that cannot prove ownership.
#[derive(Clone, Eq, PartialEq)]
pub struct InvalidReceipt {
    pub receipt_id: Option<ReceiptId>,
    pub scope: ReceiptInvalidityScope,
    pub finding: ScanFinding,
}

impl Debug for InvalidReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvalidReceipt")
            .field("receipt_id", &self.receipt_id)
            .field("scope", &self.scope)
            .field("finding_code", &self.finding.code)
            .finish()
    }
}

/// Diagnostic-only receipt evidence. It is intentionally not a writable local-state value.
#[derive(Clone, Eq, PartialEq)]
pub struct ReceiptInspection {
    pub valid: Vec<InspectedReceipt>,
    pub invalid: Vec<InvalidReceipt>,
}

impl Debug for ReceiptInspection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptInspection")
            .field("valid_count", &self.valid.len())
            .field(
                "invalid_codes",
                &self
                    .invalid
                    .iter()
                    .map(|invalid| invalid.finding.code)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ReceiptIndex {
    /// Inspects one strict local-state JSON envelope while isolating malformed receipts.
    pub fn inspect_json(input: impl AsRef<[u8]>) -> AdapterResult<ReceiptInspection> {
        Self::inspect_json_bounded(
            input.as_ref(),
            DEFAULT_MAX_INPUT_BYTES,
            DEFAULT_MAX_RECEIPTS,
            DEFAULT_MAX_RECEIPT_BYTES,
        )
    }

    pub(crate) fn inspect_json_bounded(
        input: &[u8],
        max_input_bytes: usize,
        max_receipts: usize,
        max_receipt_bytes: usize,
    ) -> AdapterResult<ReceiptInspection> {
        if input.len() > max_input_bytes {
            return Err(invalid_envelope());
        }
        let mut deserializer = serde_json::Deserializer::from_slice(input);
        let envelope = EnvelopeSeed {
            max_receipts,
            max_receipt_bytes,
        }
        .deserialize(&mut deserializer)
        .and_then(|envelope| {
            deserializer.end()?;
            Ok(envelope)
        })
        .map_err(|_| invalid_envelope())?;

        validate_raw::<SchemaVersion>(&envelope.schema_version)?;
        validate_raw::<MachineConfig>(&envelope.machine)?;
        validate_raw::<BTreeMap<BindingName, BindingResolver>>(&envelope.bindings)?;
        if let Some(pack_applications) = &envelope.pack_applications {
            validate_raw::<
                BTreeMap<kitrove_model::PackApplicationId, kitrove_model::PackApplicationClaim>,
            >(pack_applications)?;
        }
        validate_raw::<BTreeMap<ContentHash, TrustDecision>>(&envelope.trust)?;
        validate_raw::<Vec<ScanRecord>>(&envelope.scans)?;

        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        for record in envelope.receipts {
            match record.raw {
                Some(raw) => inspect_receipt(record.key, &raw, &mut valid, &mut invalid),
                None => {
                    let receipt_id = ReceiptId::parse(record.key).ok();
                    let scope = ReceiptInvalidityScope::Report;
                    invalid.push(InvalidReceipt {
                        finding: invalid_receipt_finding(receipt_id.as_ref(), &scope),
                        receipt_id,
                        scope,
                    });
                }
            }
        }
        reject_duplicate_destination_claims(&mut valid, &mut invalid);
        valid.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
        invalid.sort_by(invalid_receipt_order);
        Ok(ReceiptInspection { valid, invalid })
    }
}

fn validate_raw<T: DeserializeOwned>(raw: &RawValue) -> AdapterResult<()> {
    reject_duplicate_keys(raw.get()).map_err(|_| invalid_envelope())?;
    serde_json::from_str::<T>(raw.get())
        .map(|_| ())
        .map_err(|_| invalid_envelope())
}

fn inspect_receipt(
    raw_key: String,
    raw: &RawValue,
    valid: &mut Vec<InspectedReceipt>,
    invalid: &mut Vec<InvalidReceipt>,
) {
    let receipt_id = ReceiptId::parse(raw_key).ok();
    let duplicate_free = reject_duplicate_keys(raw.get()).is_ok();
    let scope = recover_scope(raw);
    let parsed = duplicate_free
        .then(|| serde_json::from_str::<DeploymentReceipt>(raw.get()))
        .transpose()
        .ok()
        .flatten();
    let Some(receipt) = parsed else {
        invalid.push(InvalidReceipt {
            finding: invalid_receipt_finding(receipt_id.as_ref(), &scope),
            receipt_id,
            scope,
        });
        return;
    };
    let identity_matches = receipt_id
        .as_ref()
        .zip(receipt.receipt_id().ok().as_ref())
        .is_some_and(|(stored, recomputed)| stored == recomputed);
    if !identity_matches
        || !valid_adapter_version(&receipt.adapter_version)
        || !valid_environment_revision(receipt.environment_revision.as_str())
    {
        invalid.push(InvalidReceipt {
            finding: invalid_receipt_finding(receipt_id.as_ref(), &scope),
            receipt_id,
            scope,
        });
        return;
    }
    valid.push(InspectedReceipt {
        receipt_id: receipt_id.expect("matching identity includes a parsed receipt key"),
        receipt,
    });
}

fn recover_scope(raw: &RawValue) -> ReceiptInvalidityScope {
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    deserializer
        .deserialize_map(ReceiptScopeVisitor)
        .and_then(|scope| {
            deserializer.end()?;
            Ok(scope)
        })
        .unwrap_or(ReceiptInvalidityScope::Report)
}

fn recovered_scope(
    harness: Option<HarnessId>,
    scope: Option<HarnessScope>,
    destination: Option<NormalizedDestination>,
) -> ReceiptInvalidityScope {
    match (harness, scope, destination) {
        (Some(harness), Some(scope), Some(normalized_destination)) => {
            ReceiptInvalidityScope::Destination {
                harness,
                scope,
                normalized_destination,
            }
        }
        (Some(harness), Some(scope), None) => {
            ReceiptInvalidityScope::HarnessScope { harness, scope }
        }
        (Some(harness), None, _) => ReceiptInvalidityScope::Harness(harness),
        (None, _, _) => ReceiptInvalidityScope::Report,
    }
}

struct ReceiptScopeVisitor;

impl<'de> Visitor<'de> for ReceiptScopeVisitor {
    type Value = ReceiptInvalidityScope;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("one receipt object with unambiguous ownership partition fields")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut harness = None;
        let mut scope = None;
        let mut destination = None;
        let mut may_have_shared_authority = false;
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value::<serde_json::Value>()?;
            match key.as_str() {
                "harness" if seen.insert(key.clone()) => {
                    harness = value
                        .as_str()
                        .and_then(|value| HarnessId::parse(value.to_owned()).ok());
                }
                "harness" => harness = None,
                "scope" if seen.insert(key.clone()) => {
                    scope = value.as_str().and_then(|value| match value {
                        "user" => Some(HarnessScope::User),
                        "project" => Some(HarnessScope::Project),
                        _ => None,
                    });
                }
                "scope" => scope = None,
                "destination" if seen.insert(key.clone()) => {
                    destination = value
                        .as_str()
                        .and_then(|value| NormalizedDestination::parse(value.to_owned()).ok());
                }
                "destination" => destination = None,
                "target" => {
                    may_have_shared_authority |= value.as_str().is_some_and(|target| {
                        matches!(target, "managed_instruction_region" | "managed_mcp_entry")
                    });
                }
                "logical_key" | "document_hash" => may_have_shared_authority = true,
                "shared_with" => {
                    may_have_shared_authority |= value
                        .as_array()
                        .is_none_or(|consumers| !consumers.is_empty());
                }
                "shared_adapter_versions" => {
                    may_have_shared_authority |= value
                        .as_object()
                        .is_none_or(|versions| !versions.is_empty());
                }
                _ => {}
            }
        }
        if may_have_shared_authority {
            Ok(ReceiptInvalidityScope::Report)
        } else {
            Ok(recovered_scope(harness, scope, destination))
        }
    }
}

fn reject_duplicate_destination_claims(
    valid: &mut Vec<InspectedReceipt>,
    invalid: &mut Vec<InvalidReceipt>,
) {
    type Claim = (ReceiptId, ReceiptTarget, Option<String>);

    let mut claims = BTreeMap::<NormalizedDestination, Vec<Claim>>::new();
    for record in &*valid {
        let region = match record.receipt.target {
            ReceiptTarget::WholeTarget => None,
            ReceiptTarget::ManagedInstructionRegion => {
                Some(record.receipt.asset_id.as_str().to_owned())
            }
            ReceiptTarget::ManagedMcpEntry => record.receipt.logical_key.clone(),
        };
        claims
            .entry(record.receipt.destination.clone())
            .or_default()
            .push((record.receipt_id.clone(), record.receipt.target, region));
    }

    let mut conflicts = BTreeSet::<ReceiptId>::new();
    for claims in claims.into_values() {
        if claims.len() < 2 {
            continue;
        }
        if claims
            .iter()
            .any(|(_, target, _)| *target == ReceiptTarget::WholeTarget)
        {
            for (receipt_id, _, _) in claims {
                conflicts.insert(receipt_id);
            }
            continue;
        }
        if claims
            .iter()
            .map(|(_, target, _)| target)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
        {
            for (receipt_id, _, _) in claims {
                conflicts.insert(receipt_id);
            }
            continue;
        }

        let mut region_counts = BTreeMap::new();
        for (_, _, region) in &claims {
            *region_counts.entry(region.clone()).or_insert(0_usize) += 1;
        }
        for (receipt_id, _, region) in claims {
            if region_counts.get(&region).copied().unwrap_or_default() > 1 {
                conflicts.insert(receipt_id);
            }
        }
    }

    let mut retained = Vec::with_capacity(valid.len());
    for record in valid.drain(..) {
        if conflicts.remove(&record.receipt_id) {
            let scope = ReceiptInvalidityScope::Destination {
                harness: record.receipt.harness,
                scope: record.receipt.scope,
                normalized_destination: record.receipt.destination,
            };
            invalid.push(InvalidReceipt {
                finding: conflicting_receipt_finding(&scope),
                receipt_id: Some(record.receipt_id),
                scope,
            });
        } else {
            retained.push(record);
        }
    }
    *valid = retained;
}

fn conflicting_receipt_finding(scope: &ReceiptInvalidityScope) -> ScanFinding {
    let ReceiptInvalidityScope::Destination {
        harness,
        scope,
        normalized_destination,
    } = scope
    else {
        unreachable!("duplicate valid receipt claims always recover a destination")
    };
    ScanFinding::new(
        "scan.receipt_conflict",
        FindingSeverity::Attention,
        FindingSubject::Destination {
            harness: harness.clone(),
            scope: *scope,
            normalized_destination: normalized_destination.clone(),
        },
        vec![],
        "retain exactly one valid receipt claim for this managed destination",
    )
}

fn valid_adapter_version(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
}

fn valid_environment_revision(value: &str) -> bool {
    value
        .strip_prefix("manifest:blake3:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn invalid_receipt_finding(
    receipt_id: Option<&ReceiptId>,
    scope: &ReceiptInvalidityScope,
) -> ScanFinding {
    let subject = match scope {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => FindingSubject::Destination {
            harness: harness.clone(),
            scope: *scope,
            normalized_destination: normalized_destination.clone(),
        },
        ReceiptInvalidityScope::HarnessScope { harness, .. }
        | ReceiptInvalidityScope::Harness(harness) => FindingSubject::Harness(harness.clone()),
        ReceiptInvalidityScope::Report => receipt_id
            .cloned()
            .map_or(FindingSubject::Report, FindingSubject::Receipt),
    };
    ScanFinding::new(
        "scan.receipt_invalid",
        FindingSeverity::Attention,
        subject,
        vec![],
        "repair or remove the invalid machine-local receipt before trusting ownership absence",
    )
}

fn invalid_receipt_order(left: &InvalidReceipt, right: &InvalidReceipt) -> std::cmp::Ordering {
    invalidity_key(&left.scope)
        .cmp(&invalidity_key(&right.scope))
        .then_with(|| left.receipt_id.cmp(&right.receipt_id))
}

fn invalidity_key(scope: &ReceiptInvalidityScope) -> (u8, String, String, String) {
    match scope {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => (
            0,
            harness.as_str().to_owned(),
            scope.as_str().to_owned(),
            normalized_destination.as_str().to_owned(),
        ),
        ReceiptInvalidityScope::HarnessScope { harness, scope } => (
            1,
            harness.as_str().to_owned(),
            scope.as_str().to_owned(),
            String::new(),
        ),
        ReceiptInvalidityScope::Harness(harness) => {
            (2, harness.as_str().to_owned(), String::new(), String::new())
        }
        ReceiptInvalidityScope::Report => (3, String::new(), String::new(), String::new()),
    }
}

fn invalid_envelope() -> AdapterError {
    AdapterError::new(
        "scan.local_state_invalid",
        "the machine-local state envelope is invalid and cannot provide ownership evidence",
    )
}

struct RawReceiptRecord {
    key: String,
    raw: Option<Box<RawValue>>,
}

struct RawEnvelope {
    schema_version: Box<RawValue>,
    machine: Box<RawValue>,
    bindings: Box<RawValue>,
    receipts: Vec<RawReceiptRecord>,
    pack_applications: Option<Box<RawValue>>,
    trust: Box<RawValue>,
    scans: Box<RawValue>,
}

struct EnvelopeSeed {
    max_receipts: usize,
    max_receipt_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for EnvelopeSeed {
    type Value = RawEnvelope;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(EnvelopeVisitor {
            max_receipts: self.max_receipts,
            max_receipt_bytes: self.max_receipt_bytes,
        })
    }
}

struct EnvelopeVisitor {
    max_receipts: usize,
    max_receipt_bytes: usize,
}

impl<'de> Visitor<'de> for EnvelopeVisitor {
    type Value = RawEnvelope;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("one strict local-state object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut schema_version = None;
        let mut machine = None;
        let mut bindings = None;
        let mut receipts = None;
        let mut pack_applications = None;
        let mut trust = None;
        let mut scans = None;
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate local-state field"));
            }
            match key.as_str() {
                "schema_version" => schema_version = Some(map.next_value()?),
                "machine" => machine = Some(map.next_value()?),
                "bindings" => bindings = Some(map.next_value()?),
                "receipts" => {
                    receipts = Some(map.next_value_seed(ReceiptMapSeed {
                        max_receipts: self.max_receipts,
                        max_receipt_bytes: self.max_receipt_bytes,
                    })?)
                }
                "pack_applications" => pack_applications = Some(map.next_value()?),
                "trust" => trust = Some(map.next_value()?),
                "scans" => scans = Some(map.next_value()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    return Err(de::Error::custom("unknown local-state field"));
                }
            }
        }
        Ok(RawEnvelope {
            schema_version: required(schema_version)?,
            machine: required(machine)?,
            bindings: required(bindings)?,
            receipts: required(receipts)?,
            pack_applications,
            trust: required(trust)?,
            scans: required(scans)?,
        })
    }
}

fn required<T, E: de::Error>(value: Option<T>) -> Result<T, E> {
    value.ok_or_else(|| E::custom("missing required local-state field"))
}

struct ReceiptMapSeed {
    max_receipts: usize,
    max_receipt_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for ReceiptMapSeed {
    type Value = Vec<RawReceiptRecord>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ReceiptMapVisitor {
            max_receipts: self.max_receipts,
            max_receipt_bytes: self.max_receipt_bytes,
        })
    }
}

struct ReceiptMapVisitor {
    max_receipts: usize,
    max_receipt_bytes: usize,
}

impl<'de> Visitor<'de> for ReceiptMapVisitor {
    type Value = Vec<RawReceiptRecord>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("one receipt object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut records = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate receipt map key"));
            }
            if records.len() >= self.max_receipts {
                return Err(de::Error::custom(
                    "receipt count exceeds the diagnostic bound",
                ));
            }
            let raw = map.next_value::<&'de RawValue>()?;
            records.push(RawReceiptRecord {
                key,
                raw: (raw.get().len() <= self.max_receipt_bytes).then(|| raw.to_owned()),
            });
        }
        Ok(records)
    }
}

struct DuplicateFree;

impl<'de> Deserialize<'de> for DuplicateFree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateFreeVisitor)
    }
}

struct DuplicateFreeVisitor;

impl<'de> Visitor<'de> for DuplicateFreeVisitor {
    type Value = DuplicateFree;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFree)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateFree>()?.is_some() {}
        Ok(DuplicateFree)
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<DuplicateFree>()?;
        }
        Ok(DuplicateFree)
    }
}

fn reject_duplicate_keys(input: &str) -> Result<(), ()> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    DuplicateFree::deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|_| ())
}
