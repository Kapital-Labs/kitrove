use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_adapter_api::{InstructionTargetAnchor, InstructionTargetPolicy};
use kitrove_agent_skills::{CaptureMeter, CaptureUsage};
use kitrove_instructions::{
    InstructionLimits, hash_instruction_document, hash_managed_region, inspect_managed_document,
};
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, HarnessId, HarnessScope, NormalizedDestination,
    ReceiptTarget,
};

use crate::ScanClassification;
use crate::materialization::{normalized_destination_from_path, validate_target_anchor};
use crate::read_only_fs::{
    ReadOnlyFileError, RegularFileMode, read_bounded_regular_file_with_mode,
};

/// Stable, path-free failure from read-only standing-instruction observation.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionObservationError {
    code: &'static str,
    message: &'static str,
}

impl InstructionObservationError {
    const fn new(code: &'static str, message: &'static str) -> Self {
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

impl Debug for InstructionObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionObservationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionObservationError {}

/// One exact managed region captured without exposing its authored bytes through `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedInstructionRegion {
    asset_id: AssetId,
    body: Vec<u8>,
    exact_region: Vec<u8>,
    exact_region_hash: ContentHash,
    observation_revision: ContentHash,
}

impl ObservedInstructionRegion {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn exact_region(&self) -> &[u8] {
        &self.exact_region
    }

    #[must_use]
    pub const fn exact_region_hash(&self) -> &ContentHash {
        &self.exact_region_hash
    }

    /// Stable identity over logical policy authority and exact bytes, excluding machine paths.
    #[must_use]
    pub const fn observation_revision(&self) -> &ContentHash {
        &self.observation_revision
    }
}

impl Debug for ObservedInstructionRegion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedInstructionRegion")
            .field("asset_id", &self.asset_id)
            .field("body_byte_count", &self.body.len())
            .field("region_byte_count", &self.exact_region.len())
            .field("exact_region_hash", &self.exact_region_hash)
            .field("observation_revision", &self.observation_revision)
            .finish()
    }
}

/// Strict read-only view of every managed region in one co-owned instruction file.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionDocumentObservation {
    policy: InstructionTargetPolicy,
    destination: NormalizedDestination,
    document: Option<Vec<u8>>,
    mode: RegularFileMode,
    regions: Option<BTreeMap<AssetId, ObservedInstructionRegion>>,
    document_hash: Option<ContentHash>,
    document_byte_count: Option<usize>,
}

impl InstructionDocumentObservation {
    #[must_use]
    pub fn region(&self, asset_id: &AssetId) -> Option<&ObservedInstructionRegion> {
        self.regions.as_ref()?.get(asset_id)
    }

    pub fn regions(&self) -> impl Iterator<Item = &ObservedInstructionRegion> {
        self.regions.iter().flat_map(|regions| regions.values())
    }

    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.policy.harness
    }

    #[must_use]
    pub const fn scope(&self) -> HarnessScope {
        self.policy.scope
    }

    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    /// Returns the exact compiled policy used to produce this observation.
    #[must_use]
    pub const fn policy(&self) -> &InstructionTargetPolicy {
        &self.policy
    }

    pub(crate) fn document_bytes(&self) -> Option<&[u8]> {
        self.document.as_deref()
    }

    pub(crate) fn document_text(&self) -> Option<&str> {
        self.document
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }

    pub(crate) fn has_same_physical_authority(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.document == other.document
            && self.mode == other.mode
            && self.document_hash == other.document_hash
            && self.document_byte_count == other.document_byte_count
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.regions.is_some()
    }

    #[must_use]
    pub const fn document_hash(&self) -> Option<&ContentHash> {
        self.document_hash.as_ref()
    }

    #[must_use]
    pub const fn document_byte_count(&self) -> Option<usize> {
        self.document_byte_count
    }
}

impl Debug for InstructionDocumentObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionDocumentObservation")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("policy_line", &self.policy.policy_line)
            .field(
                "region_count",
                &self.regions.as_ref().map(BTreeMap::len).unwrap_or_default(),
            )
            .field("present", &self.is_present())
            .field("document_hash", &self.document_hash)
            .field("document_byte_count", &self.document_byte_count)
            .finish()
    }
}

/// Reads and strictly parses one compiled instruction target without following links or mutating it.
pub fn observe_instruction_document(
    anchor: &Path,
    policy: &InstructionTargetPolicy,
    limits: InstructionLimits,
) -> Result<InstructionDocumentObservation, InstructionObservationError> {
    observe_instruction_document_metered(anchor, policy, limits, &mut CaptureUsage::default())
}

/// Reads one instruction document while charging a caller-owned request-global capture meter.
pub fn observe_instruction_document_metered(
    anchor: &Path,
    policy: &InstructionTargetPolicy,
    limits: InstructionLimits,
    meter: &mut impl CaptureMeter,
) -> Result<InstructionDocumentObservation, InstructionObservationError> {
    policy.validate().map_err(|_| {
        observation_error(
            "instruction.policy_invalid",
            "instruction target policy is internally inconsistent",
        )
    })?;
    validate_target_anchor(anchor).map_err(|_| {
        observation_error(
            "instruction.anchor_invalid",
            "instruction target anchor must be absolute without relative components",
        )
    })?;
    let path = anchor.join(policy.relative_document.as_str());
    let destination = normalized_destination_from_path(&path).map_err(|_| {
        observation_error(
            "instruction.destination_invalid",
            "instruction target is not a supported normalized destination",
        )
    })?;
    if !meter.try_file_attempt() {
        return Err(observation_error(
            "instruction.capture_limit",
            "instruction observation exhausted the request-wide file capture limit",
        ));
    }
    let remaining_bytes = usize::try_from(meter.remaining_bytes()).unwrap_or(usize::MAX);
    let read_limit = limits.max_document_bytes.min(remaining_bytes);
    let observed_file = match read_bounded_regular_file_with_mode(&path, read_limit) {
        Ok(file) => file,
        Err(ReadOnlyFileError::Missing) => {
            return Ok(InstructionDocumentObservation {
                policy: policy.clone(),
                destination,
                document: None,
                mode: RegularFileMode::conservative(),
                regions: None,
                document_hash: None,
                document_byte_count: None,
            });
        }
        Err(ReadOnlyFileError::Unsafe) => {
            return Err(observation_error(
                "instruction.document_unsafe",
                "instruction document could not be read without following or racing an unsafe path",
            ));
        }
        Err(ReadOnlyFileError::Limit) => {
            let (code, message) = if read_limit < limits.max_document_bytes {
                (
                    "instruction.capture_limit",
                    "instruction observation exhausted the request-wide byte capture limit",
                )
            } else {
                (
                    "instruction.document_limit",
                    "instruction document exceeds the configured observation byte limit",
                )
            };
            return Err(observation_error(code, message));
        }
    };
    let bytes = observed_file.bytes;
    if !meter.try_charge_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)) {
        return Err(observation_error(
            "instruction.capture_limit",
            "instruction observation exhausted the request-wide byte capture limit",
        ));
    }
    let parsed = inspect_managed_document(&bytes, limits).map_err(|_| {
        observation_error(
            "instruction.document_invalid",
            "instruction document contains invalid managed-region structure",
        )
    })?;

    let mut regions = BTreeMap::new();
    for region in parsed.regions() {
        let exact_region = bytes[region.range().clone()].to_vec();
        let body = bytes[region.body_range().clone()].to_vec();
        let exact_region_hash = hash_managed_region(&exact_region);
        let observed = ObservedInstructionRegion {
            asset_id: region.asset_id().clone(),
            observation_revision: instruction_observation_revision(
                policy,
                region.asset_id(),
                &exact_region_hash,
            ),
            exact_region_hash,
            body,
            exact_region,
        };
        regions.insert(observed.asset_id.clone(), observed);
    }
    let document_hash = hash_instruction_document(&bytes);
    let document_byte_count = bytes.len();
    Ok(InstructionDocumentObservation {
        policy: policy.clone(),
        destination,
        document: Some(bytes),
        mode: observed_file.mode,
        document_hash: Some(document_hash),
        document_byte_count: Some(document_byte_count),
        regions: Some(regions),
    })
}

/// Revalidates one exact managed region directly from receipt-bound destination authority.
pub(crate) fn observe_instruction_region_hash(
    destination: &NormalizedDestination,
    asset_id: &AssetId,
    limits: InstructionLimits,
) -> Option<ContentHash> {
    let observed = read_bounded_regular_file_with_mode(
        Path::new(destination.as_str()),
        limits.max_document_bytes,
    )
    .ok()?;
    let document = inspect_managed_document(&observed.bytes, limits).ok()?;
    let region = document
        .regions()
        .find(|region| region.asset_id() == asset_id)?;
    Some(hash_managed_region(&observed.bytes[region.range().clone()]))
}

fn instruction_observation_revision(
    policy: &InstructionTargetPolicy,
    asset_id: &AssetId,
    exact_region_hash: &ContentHash,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-observation-v1\0");
    hasher.update(&[match policy.anchor {
        InstructionTargetAnchor::Scope => 0,
        InstructionTargetAnchor::HarnessConfiguration => 1,
    }]);
    for value in [
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_document.as_str(),
        asset_id.as_str(),
        exact_region_hash.as_str(),
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

/// Classifies one logical managed region from read-only observation and optional receipt authority.
pub fn classify_instruction_region(
    observation: &InstructionDocumentObservation,
    asset_id: &AssetId,
    receipt: Option<&DeploymentReceipt>,
) -> Result<Option<ScanClassification>, InstructionObservationError> {
    if let Some(receipt) = receipt {
        if receipt.receipt_id().is_err()
            || receipt.target != ReceiptTarget::ManagedInstructionRegion
            || receipt.asset_id != *asset_id
            || receipt.scope != observation.scope()
            || receipt.destination != observation.destination
            || !receipt
                .consumers()
                .any(|consumer| consumer == observation.harness())
            || receipt_adapter_version(receipt, observation.harness())
                != Some(observation.policy().adapter_version)
        {
            return Err(observation_error(
                "instruction.receipt_invalid",
                "receipt authority does not identify the selected managed instruction region",
            ));
        }
        return Ok(Some(match observation.region(asset_id) {
            None => ScanClassification::MissingManaged,
            Some(region) if region.exact_region_hash() == &receipt.rendered_hash => {
                ScanClassification::ManagedUnchanged
            }
            Some(_) => ScanClassification::ManagedModified,
        }));
    }

    Ok(observation
        .region(asset_id)
        .map(|_| ScanClassification::Unmanaged))
}

fn receipt_adapter_version<'a>(
    receipt: &'a DeploymentReceipt,
    harness: &HarnessId,
) -> Option<&'a str> {
    if &receipt.harness == harness {
        Some(receipt.adapter_version.as_str())
    } else {
        receipt
            .shared_adapter_versions
            .get(harness)
            .map(String::as_str)
    }
}

const fn observation_error(
    code: &'static str,
    message: &'static str,
) -> InstructionObservationError {
    InstructionObservationError::new(code, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use kitrove_adapter_api::{EvidenceRef, InstructionTargetAnchor, PolicyLine, ScanLimits};
    use kitrove_instructions::{InstructionBody, render_managed_region};
    use kitrove_model::{HarnessId, HarnessScope, NormalizedDestination, Revision};

    use super::*;

    fn asset() -> AssetId {
        AssetId::parse("shared-rules").unwrap()
    }

    fn policy() -> InstructionTargetPolicy {
        InstructionTargetPolicy {
            harness: HarnessId::Codex,
            scope: HarnessScope::Project,
            policy_line: PolicyLine::CodexCurrent,
            anchor: InstructionTargetAnchor::Scope,
            relative_document: kitrove_model::PortablePath::parse("AGENTS.md").unwrap(),
            adapter_version: "test/1",
            evidence: EvidenceRef::parse("test.instructions").unwrap(),
        }
    }

    fn receipt(
        rendered_hash: ContentHash,
        observation: &InstructionDocumentObservation,
    ) -> DeploymentReceipt {
        DeploymentReceipt {
            asset_id: asset(),
            harness: HarnessId::Codex,
            scope: HarnessScope::Project,
            destination: observation.destination().clone(),
            target: ReceiptTarget::ManagedInstructionRegion,
            logical_key: None,
            shared_with: BTreeSet::new(),
            shared_adapter_versions: Default::default(),
            source_hash: ContentHash::digest(b"source"),
            rendered_hash,
            document_hash: None,
            prior_hash: None,
            adapter_version: "test/1".to_owned(),
            environment_revision: Revision::parse("manifest:test").unwrap(),
        }
    }

    #[test]
    fn observes_and_classifies_exact_region_without_exposing_body_in_debug() {
        let root = tempfile::tempdir().unwrap();
        let body = InstructionBody::parse("secret-shaped-test-sentinel", 1024).unwrap();
        let (region, rendered_hash) = render_managed_region(&asset(), &body).unwrap();
        std::fs::write(root.path().join("AGENTS.md"), format!("human\n\n{region}")).unwrap();
        let anchor = root.path().canonicalize().unwrap();

        let observation =
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default()).unwrap();
        assert_eq!(observation.regions().count(), 1);
        assert_eq!(
            observation.region(&asset()).unwrap().body(),
            body.as_str().as_bytes()
        );
        assert!(
            observation
                .document_bytes()
                .unwrap()
                .starts_with(b"human\n\n")
        );
        assert_eq!(observation.policy(), &policy());
        assert!(!format!("{observation:?}").contains("sentinel"));
        assert_eq!(
            classify_instruction_region(
                &observation,
                &asset(),
                Some(&receipt(rendered_hash, &observation))
            )
            .unwrap(),
            Some(ScanClassification::ManagedUnchanged)
        );
    }

    #[test]
    fn missing_modified_and_unmanaged_regions_classify_independently() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let missing =
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default()).unwrap();
        assert!(!missing.is_present());
        assert_eq!(
            classify_instruction_region(
                &missing,
                &asset(),
                Some(&receipt(ContentHash::digest(b"x"), &missing))
            )
            .unwrap(),
            Some(ScanClassification::MissingManaged)
        );

        let (region, _) =
            render_managed_region(&asset(), &InstructionBody::parse("body", 1024).unwrap())
                .unwrap();
        std::fs::write(root.path().join("AGENTS.md"), region).unwrap();
        let observation =
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default()).unwrap();
        assert_eq!(
            classify_instruction_region(&observation, &asset(), None).unwrap(),
            Some(ScanClassification::Unmanaged)
        );
        assert_eq!(
            classify_instruction_region(
                &observation,
                &asset(),
                Some(&receipt(ContentHash::digest(b"other"), &observation)),
            )
            .unwrap(),
            Some(ScanClassification::ManagedModified)
        );
    }

    #[test]
    fn malformed_or_linked_documents_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let path = root.path().join("AGENTS.md");
        std::fs::write(&path, "<!-- kitrove:instruction malformed -->\n").unwrap();
        assert_eq!(
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default(),)
                .unwrap_err()
                .code(),
            "instruction.document_invalid"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            std::fs::remove_file(&path).unwrap();
            let target = root.path().join("target");
            std::fs::write(&target, "safe").unwrap();
            symlink(&target, &path).unwrap();
            assert_eq!(
                observe_instruction_document(&anchor, &policy(), InstructionLimits::default(),)
                    .unwrap_err()
                    .code(),
                "instruction.document_unsafe"
            );
        }
    }

    #[test]
    fn metered_observation_refuses_request_wide_file_and_byte_exhaustion() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        std::fs::write(root.path().join("AGENTS.md"), "three bytes and more").unwrap();

        let file_limits = ScanLimits {
            max_capture_files: 0,
            ..ScanLimits::default()
        };
        let mut file_budget = crate::ScanBudget::new(file_limits);
        assert_eq!(
            observe_instruction_document_metered(
                &anchor,
                &policy(),
                InstructionLimits::default(),
                &mut file_budget,
            )
            .unwrap_err()
            .code(),
            "instruction.capture_limit"
        );

        let byte_limits = ScanLimits {
            max_capture_bytes: 3,
            ..ScanLimits::default()
        };
        let mut byte_budget = crate::ScanBudget::new(byte_limits);
        assert_eq!(
            observe_instruction_document_metered(
                &anchor,
                &policy(),
                InstructionLimits::default(),
                &mut byte_budget,
            )
            .unwrap_err()
            .code(),
            "instruction.capture_limit"
        );
    }

    #[test]
    fn classification_rejects_receipt_from_another_authority_boundary() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let observation =
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default()).unwrap();
        let mut wrong = receipt(ContentHash::digest(b"region"), &observation);
        wrong.destination = NormalizedDestination::parse("/different/AGENTS.md").unwrap();
        assert_eq!(
            classify_instruction_region(&observation, &asset(), Some(&wrong))
                .unwrap_err()
                .code(),
            "instruction.receipt_invalid"
        );

        let mut stale_policy = receipt(ContentHash::digest(b"region"), &observation);
        stale_policy.adapter_version = "stale-policy/1".to_owned();
        assert_eq!(
            classify_instruction_region(&observation, &asset(), Some(&stale_policy))
                .unwrap_err()
                .code(),
            "instruction.receipt_invalid"
        );

        assert_eq!(
            observe_instruction_document(
                Path::new("relative"),
                &policy(),
                InstructionLimits::default(),
            )
            .unwrap_err()
            .code(),
            "instruction.anchor_invalid"
        );

        let mut invalid_policy = policy();
        invalid_policy.policy_line = PolicyLine::ClaudeCurrent;
        assert_eq!(
            observe_instruction_document(&anchor, &invalid_policy, InstructionLimits::default(),)
                .unwrap_err()
                .code(),
            "instruction.policy_invalid"
        );
    }
}
