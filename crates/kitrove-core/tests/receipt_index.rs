#![forbid(unsafe_code)]

use kitrove_core::{ReceiptIndex, ReceiptInvalidityScope};
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, HarnessId, HarnessScope, NormalizedDestination,
    ReceiptTarget, Revision,
};
use serde_json::{Map, Value, json};

#[cfg(any(target_os = "linux", target_os = "macos"))]
const OVERSIZED_RECEIPT_CHILD_MODE: &str = "KITROVE_OVERSIZED_RECEIPT_CHILD_MODE";

fn hash(label: &str) -> ContentHash {
    ContentHash::digest(label.as_bytes())
}

fn receipt(asset: &str, destination: &str) -> DeploymentReceipt {
    DeploymentReceipt {
        asset_id: AssetId::parse(asset).unwrap(),
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        destination: NormalizedDestination::parse(destination).unwrap(),
        target: Default::default(),
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: hash(&format!("source-{asset}")),
        rendered_hash: hash(&format!("rendered-{asset}")),
        document_hash: None,
        prior_hash: None,
        adapter_version: "claude-current/1".to_owned(),
        environment_revision: Revision::parse(format!(
            "manifest:blake3:{}",
            blake3::hash(b"manifest").to_hex()
        ))
        .unwrap(),
    }
}

fn receipt_pair(asset: &str, destination: &str) -> (String, Value) {
    let receipt = receipt(asset, destination);
    persisted_receipt(receipt)
}

fn persisted_receipt(receipt: DeploymentReceipt) -> (String, Value) {
    (
        receipt.receipt_id().unwrap().as_str().to_owned(),
        serde_json::to_value(receipt).unwrap(),
    )
}

fn mcp_receipt(asset: &str, key: &str, destination: &str) -> DeploymentReceipt {
    let mut receipt = receipt(asset, destination);
    receipt.target = ReceiptTarget::ManagedMcpEntry;
    receipt.logical_key = Some(key.to_owned());
    receipt.document_hash = Some(hash(&format!("document-{asset}")));
    receipt
}

fn envelope(receipts: &str) -> String {
    format!(
        r#"{{"schema_version":1,"machine":{{"id":"machine","active_profile":null,"enabled_targets":[],"harness_roots":{{}}}},"bindings":{{}},"receipts":{receipts},"trust":{{}},"scans":[]}}"#
    )
}

fn receipt_map(entries: &[(String, Value)]) -> String {
    let map = entries.iter().cloned().collect::<Map<String, Value>>();
    serde_json::to_string(&Value::Object(map)).unwrap()
}

#[test]
fn malformed_receipt_does_not_erase_valid_sibling_ownership() {
    let valid = receipt_pair("valid", "/safe/skills/valid");
    let mut malformed = receipt_pair("malformed", "/safe/skills/malformed");
    malformed
        .1
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), json!("sentinel-raw-json-value"));
    let json = envelope(&receipt_map(&[valid, malformed]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();

    assert_eq!(inspection.valid.len(), 1);
    assert_eq!(inspection.invalid.len(), 1);
    assert_eq!(inspection.valid[0].receipt.asset_id.as_str(), "valid");
    assert_eq!(inspection.invalid[0].finding.code, "scan.receipt_invalid");
    assert!(!format!("{inspection:?}").contains("sentinel-raw-json-value"));
}

#[test]
fn known_pack_application_authority_preserves_strict_receipt_inspection() {
    let json = envelope(&receipt_map(&[receipt_pair("valid", "/safe/skills/valid")]))
        .replace(",\"trust\"", ",\"pack_applications\":{},\"trust\"");
    let inspection = ReceiptIndex::inspect_json(json).unwrap();
    assert_eq!(inspection.valid.len(), 1);

    let malformed = envelope("{}").replace(",\"trust\"", ",\"pack_applications\":[],\"trust\"");
    assert!(ReceiptIndex::inspect_json(malformed).is_err());
}

#[test]
fn malformed_shared_instruction_receipt_invalidates_report_wide_absence() {
    let mut shared = receipt("shared", "/safe/AGENTS.md");
    shared.target = ReceiptTarget::ManagedInstructionRegion;
    shared.shared_with.insert(HarnessId::Pi);
    shared
        .shared_adapter_versions
        .insert(HarnessId::Pi, "pi-latest/1".to_owned());
    let mut pair = persisted_receipt(shared);
    pair.1
        .as_object_mut()
        .unwrap()
        .insert("adapter_version".to_owned(), json!(""));

    let inspection = ReceiptIndex::inspect_json(envelope(&receipt_map(&[pair]))).unwrap();

    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 1);
    assert_eq!(inspection.invalid[0].scope, ReceiptInvalidityScope::Report);
}

#[test]
fn duplicate_top_level_and_receipt_map_keys_fail_the_envelope() {
    let receipt = receipt_pair("valid", "/safe/skills/valid");
    let encoded = serde_json::to_string(&receipt.1).unwrap();
    let duplicate_top = r#"{"schema_version":1,"schema_version":1,"machine":{"id":"machine","active_profile":null,"enabled_targets":[],"harness_roots":{}},"bindings":{},"receipts":{},"trust":{},"scans":[]}"#.to_owned();
    let duplicate_receipt = envelope(&format!(
        r#"{{"{}":{},"{}":{}}}"#,
        receipt.0, encoded, receipt.0, encoded
    ));

    for input in [duplicate_top, duplicate_receipt] {
        let error = ReceiptIndex::inspect_json(input).unwrap_err();
        assert_eq!(error.code, "scan.local_state_invalid");
    }
}

#[test]
fn duplicate_receipt_fields_cannot_forge_a_narrower_invalidity_partition() {
    let cases = [
        ("harness", json!("secret-duplicate-harness"), "report"),
        ("scope", json!("project"), "harness"),
        (
            "destination",
            json!("/safe/skills/secret-duplicate-destination"),
            "harness-scope",
        ),
        (
            "source_hash",
            json!(hash("secret-duplicate-source")),
            "destination",
        ),
    ];

    for (field, duplicate_value, expected_partition) in cases {
        let pair = receipt_pair("duplicate-field", "/safe/skills/original");
        let mut encoded = serde_json::to_string(&pair.1).unwrap();
        let marker = format!(
            r#""{field}":{}"#,
            serde_json::to_string(&pair.1[field]).unwrap()
        );
        let replacement = format!(
            r#"{marker},"{field}":{}"#,
            serde_json::to_string(&duplicate_value).unwrap()
        );
        encoded = encoded.replacen(&marker, &replacement, 1);
        let inspection =
            ReceiptIndex::inspect_json(envelope(&format!(r#"{{"{}":{encoded}}}"#, pair.0)))
                .unwrap();

        assert!(inspection.valid.is_empty());
        assert_eq!(inspection.invalid.len(), 1);
        let actual_partition = match &inspection.invalid[0].scope {
            ReceiptInvalidityScope::Report => "report",
            ReceiptInvalidityScope::Harness(_) => "harness",
            ReceiptInvalidityScope::HarnessScope { .. } => "harness-scope",
            ReceiptInvalidityScope::Destination { .. } => "destination",
        };
        assert_eq!(actual_partition, expected_partition, "field {field}");
        assert!(!format!("{inspection:?}").contains("secret"));
    }
}

#[test]
fn every_invalid_non_receipt_field_fails_the_envelope() {
    let valid = envelope("{}");
    let cases = [
        valid.replace("\"schema_version\":1", "\"schema_version\":2"),
        valid.replace("\"id\":\"machine\"", "\"id\":\"INVALID\""),
        valid.replace(
            "\"bindings\":{}",
            r#""bindings":{"INVALID":{"type":"environment","variable":"TOKEN"}}"#,
        ),
        valid.replace(
            "\"trust\":{}",
            r#""trust":{"not-a-hash":{"decision":"trusted","rationale":"x"}}"#,
        ),
        valid.replace(
            "\"scans\":[]",
            r#""scans":[{"harness":"claude","observed_at":"now","discovered_assets":"many"}]"#,
        ),
        valid.replace("\"receipts\":{}", r#""receipts":[]"#),
        valid.replacen('{', r#"{"unexpected":"sentinel-top-level","#, 1),
        valid.replace("\"scans\":[]", ""),
        "[]".to_owned(),
    ];

    for input in cases {
        let error = ReceiptIndex::inspect_json(input).unwrap_err();
        assert_eq!(error.code, "scan.local_state_invalid");
        assert!(!format!("{error:?}").contains("sentinel-top-level"));
    }
}

#[test]
fn bad_receipt_keys_and_unknown_receipt_fields_are_localized() {
    let bad_key_receipt = receipt_pair("bad-key", "/safe/skills/bad-key").1;
    let mut unknown_field = receipt_pair("unknown-field", "/safe/skills/unknown-field");
    unknown_field
        .1
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(true));
    let json = envelope(&receipt_map(&[
        ("INVALID-RECEIPT-KEY".to_owned(), bad_key_receipt),
        unknown_field,
    ]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();

    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
    assert!(
        inspection
            .invalid
            .iter()
            .all(|invalid| invalid.finding.code == "scan.receipt_invalid")
    );
}

#[test]
fn recomputed_receipt_identity_mismatch_is_localized() {
    let stored_key = receipt_pair("stored-key", "/safe/skills/stored-key").0;
    let different_value = receipt_pair("different-value", "/safe/skills/different-value").1;
    let inspection =
        ReceiptIndex::inspect_json(envelope(&receipt_map(&[(stored_key, different_value)])))
            .unwrap();

    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 1);
    assert_eq!(inspection.invalid[0].finding.code, "scan.receipt_invalid");
}

#[test]
fn two_structurally_valid_receipts_cannot_claim_one_destination() {
    let first = receipt_pair("first", "/safe/skills/shared");
    let second = receipt_pair("second", "/safe/skills/shared");
    let json = envelope(&receipt_map(&[first, second]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();

    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
    assert!(
        inspection
            .invalid
            .iter()
            .all(|invalid| invalid.finding.code == "scan.receipt_conflict")
    );
}

#[test]
fn distinct_managed_regions_can_share_one_physical_document() {
    let destination = "/safe/AGENTS.md";
    let mut first = receipt("first", destination);
    first.target = ReceiptTarget::ManagedInstructionRegion;
    let mut second = receipt("second", destination);
    second.target = ReceiptTarget::ManagedInstructionRegion;
    let json = envelope(&receipt_map(&[
        persisted_receipt(first),
        persisted_receipt(second),
    ]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();
    assert_eq!(inspection.valid.len(), 2);
    assert!(inspection.invalid.is_empty());
}

#[test]
fn distinct_mcp_keys_can_share_a_document_but_duplicate_keys_conflict() {
    let destination = "/safe/.claude.json";
    let first = mcp_receipt("first", "company-tools", destination);
    let second = mcp_receipt("second", "company-search", destination);
    let inspection = ReceiptIndex::inspect_json(envelope(&receipt_map(&[
        persisted_receipt(first.clone()),
        persisted_receipt(second),
    ])))
    .unwrap();
    assert_eq!(inspection.valid.len(), 2);
    assert!(inspection.invalid.is_empty());

    let duplicate = mcp_receipt("duplicate", "company-tools", destination);
    let inspection = ReceiptIndex::inspect_json(envelope(&receipt_map(&[
        persisted_receipt(first),
        persisted_receipt(duplicate),
    ])))
    .unwrap();
    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
}

#[test]
fn different_structured_ownership_models_cannot_share_one_document() {
    let destination = "/safe/shared.conf";
    let mut instruction = receipt("instructions", destination);
    instruction.target = ReceiptTarget::ManagedInstructionRegion;
    let mcp = mcp_receipt("tools", "company-tools", destination);
    let inspection = ReceiptIndex::inspect_json(envelope(&receipt_map(&[
        persisted_receipt(instruction),
        persisted_receipt(mcp),
    ])))
    .unwrap();
    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
}

#[test]
fn duplicate_region_claims_from_different_harnesses_invalidate_both() {
    let destination = "/safe/AGENTS.md";
    let mut shared = receipt("shared", destination);
    shared.harness = HarnessId::Codex;
    shared.target = ReceiptTarget::ManagedInstructionRegion;
    shared.shared_with = std::collections::BTreeSet::from([HarnessId::Pi]);
    shared.shared_adapter_versions =
        std::collections::BTreeMap::from([(HarnessId::Pi, "pi-instructions/1".to_owned())]);

    let mut duplicate = receipt("shared", destination);
    duplicate.harness = HarnessId::OpenCode;
    duplicate.target = ReceiptTarget::ManagedInstructionRegion;
    let json = envelope(&receipt_map(&[
        persisted_receipt(shared),
        persisted_receipt(duplicate),
    ]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();
    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
    assert!(
        inspection
            .invalid
            .iter()
            .all(|record| record.finding.code == "scan.receipt_conflict")
    );
}

#[test]
fn whole_target_claim_conflicts_with_every_region_in_that_document() {
    let destination = "/safe/AGENTS.md";
    let whole = receipt("legacy-whole", destination);
    let mut region = receipt("managed-region", destination);
    region.target = ReceiptTarget::ManagedInstructionRegion;
    let json = envelope(&receipt_map(&[
        persisted_receipt(whole),
        persisted_receipt(region),
    ]));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();
    assert!(inspection.valid.is_empty());
    assert_eq!(inspection.invalid.len(), 2);
}

#[test]
fn noncanonical_receipt_evidence_is_localized_without_exposing_authored_values() {
    let cases = [
        ("asset_id", json!("INVALID-secret-asset-canary")),
        ("harness", json!("secret-harness-canary")),
        ("scope", json!("secret-scope-canary")),
        ("destination", json!("relative/secret-destination-canary")),
        ("adapter_version", json!("line\nsecret-adapter-canary")),
        (
            "environment_revision",
            json!("manifest:blake3:1234-secret-revision-canary"),
        ),
        ("source_hash", json!("blake3:ABC-secret-hash-canary")),
        ("rendered_hash", json!("secret-rendered-hash-canary")),
        ("prior_hash", json!("secret-prior-hash-canary")),
    ];

    for (field, value) in cases {
        let mut pair = receipt_pair("invalid", "/safe/skills/invalid");
        pair.1
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        let inspection = ReceiptIndex::inspect_json(envelope(&receipt_map(&[pair]))).unwrap();
        assert!(inspection.valid.is_empty());
        assert_eq!(inspection.invalid.len(), 1);
        assert_eq!(inspection.invalid[0].finding.code, "scan.receipt_invalid");
        let debug = format!("{inspection:?}");
        assert!(!debug.contains("secret"));
    }
}

#[test]
fn oversized_receipt_record_is_localized_without_erasing_a_valid_sibling() {
    let valid = receipt_pair("valid", "/safe/skills/valid");
    let oversized_key = receipt_pair("oversized", "/safe/skills/oversized").0;
    let oversized = "x".repeat(1024 * 1024 + 1);
    let json = envelope(&format!(
        r#"{{"{}":{},"{}":{{"padding":"{}"}}}}"#,
        valid.0,
        serde_json::to_string(&valid.1).unwrap(),
        oversized_key,
        oversized
    ));

    let inspection = ReceiptIndex::inspect_json(json).unwrap();

    assert_eq!(inspection.valid.len(), 1);
    assert_eq!(inspection.valid[0].receipt.asset_id.as_str(), "valid");
    assert_eq!(inspection.invalid.len(), 1);
    assert_eq!(inspection.invalid[0].finding.code, "scan.receipt_invalid");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn near_global_oversized_envelope() -> Vec<u8> {
    const PADDING_BYTES: usize = 31 * 1024 * 1024;

    let oversized_key = receipt_pair("oversized", "/safe/skills/oversized").0;
    let prefix = format!(
        r#"{{"schema_version":1,"machine":{{"id":"machine","active_profile":null,"enabled_targets":[],"harness_roots":{{}}}},"bindings":{{}},"receipts":{{"{oversized_key}":{{"padding":""#
    );
    let suffix = br#""}},"trust":{},"scans":[]}"#;
    let mut input = Vec::with_capacity(prefix.len() + PADDING_BYTES + suffix.len());
    input.extend_from_slice(prefix.as_bytes());
    input.resize(input.len() + PADDING_BYTES, b'x');
    input.extend_from_slice(suffix);
    assert!(input.len() < 32 * 1024 * 1024);
    input
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn child_peak_resident_bytes(mode: &str) -> u64 {
    use std::process::Command;

    let mut command = Command::new("/usr/bin/time");
    #[cfg(target_os = "macos")]
    command.arg("-l");
    #[cfg(target_os = "linux")]
    command.arg("-v");
    let output = command
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "near_global_oversized_receipt_is_rejected_without_large_raw_copy",
            "--nocapture",
        ])
        .env(OVERSIZED_RECEIPT_CHILD_MODE, mode)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "measurement child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    #[cfg(target_os = "macos")]
    let peak = stderr.lines().find_map(|line| {
        line.contains("maximum resident set size")
            .then(|| line.split_whitespace().next()?.parse::<u64>().ok())
            .flatten()
    });
    #[cfg(target_os = "linux")]
    let peak = stderr.lines().find_map(|line| {
        line.contains("Maximum resident set size (kbytes)")
            .then(|| {
                line.split_whitespace()
                    .last()?
                    .parse::<u64>()
                    .ok()
                    .map(|kilobytes| kilobytes * 1024)
            })
            .flatten()
    });
    peak.unwrap_or_else(|| panic!("missing peak resident size in: {stderr}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn near_global_oversized_receipt_is_rejected_without_large_raw_copy() {
    if let Ok(mode) = std::env::var(OVERSIZED_RECEIPT_CHILD_MODE) {
        let input = near_global_oversized_envelope();
        std::hint::black_box(&input);
        if mode == "parse" {
            let inspection = ReceiptIndex::inspect_json(&input).unwrap();
            assert!(inspection.valid.is_empty());
            assert_eq!(inspection.invalid.len(), 1);
            assert_eq!(inspection.invalid[0].finding.code, "scan.receipt_invalid");
        }
        return;
    }

    let build_peak = child_peak_resident_bytes("build");
    let parse_peak = child_peak_resident_bytes("parse");
    let extra_peak = parse_peak.saturating_sub(build_peak);
    assert!(
        extra_peak <= 8 * 1024 * 1024,
        "oversized receipt parsing added {extra_peak} resident bytes (build={build_peak}, parse={parse_peak})"
    );
}
