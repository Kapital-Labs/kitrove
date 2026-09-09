use super::*;
use crate::tests::{ARCHIVE_DIGEST, ARCHIVE_NAME, fixture_policy};

fn fixture() -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/github-actions-public-slsa-v1.json"
    ))
    .unwrap();
    serde_json::to_vec(&value).unwrap()
}

fn verify(bytes: &[u8]) -> Result<(), ReleaseAttestationError> {
    crate::verify_attestation(ARCHIVE_NAME, ARCHIVE_DIGEST, bytes, &fixture_policy())
}

fn invalid_signature() -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
    let signature = value["dsseEnvelope"]["signatures"][0]["sig"]
        .as_str()
        .unwrap();
    let changed = format!(
        "{}{}",
        if signature.starts_with('A') { "B" } else { "A" },
        &signature[1..]
    );
    value["dsseEnvelope"]["signatures"][0]["sig"] = changed.into();
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn selection_cryptographically_verifies_and_preserves_one_exact_record() {
    let valid = fixture();
    for framing in ["", "\n", "\r\n"] {
        let text = format!("  {}  {framing}", std::str::from_utf8(&valid).unwrap());
        let selected = select_bundle(text.as_bytes(), verify).unwrap();
        assert_eq!(
            selected,
            format!("  {}  ", std::str::from_utf8(&valid).unwrap()).as_bytes()
        );
        verify(selected).unwrap();
    }
    let wrong = invalid_signature();
    for records in [
        [wrong.as_slice(), valid.as_slice()],
        [valid.as_slice(), wrong.as_slice()],
    ] {
        let collection = records.join(&b'\n');
        assert_eq!(select_bundle(&collection, verify).unwrap(), valid);
    }
}

#[test]
fn zero_and_multiple_matches_are_not_selection_authority() {
    assert_eq!(
        select_bundle(&invalid_signature(), verify),
        Err(BundleSelectionError::NoMatchingBundle)
    );
    let duplicate = [fixture(), fixture()].join(&b'\n');
    assert_eq!(
        select_bundle(&duplicate, verify),
        Err(BundleSelectionError::AmbiguousBundles)
    );
    let valid = fixture();
    let changed_digest =
        |bytes: &[u8]| crate::verify_attestation(ARCHIVE_NAME, [0; 32], bytes, &fixture_policy());
    assert_eq!(
        select_bundle(&valid, changed_digest),
        Err(BundleSelectionError::NoMatchingBundle)
    );
}

#[test]
fn invalid_framing_and_shapes_fail_before_any_crypto_work() {
    let valid = fixture();
    let mut duplicate_key = valid.clone();
    duplicate_key.splice(1..1, b"\"mediaType\":null,".iter().copied());
    for input in [
        Vec::new(),
        vec![0xff],
        b"\n".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        [b"\n".as_slice(), &valid].concat(),
        [&valid, b"\n\n".as_slice()].concat(),
        [&valid, b"\n{}".as_slice()].concat(),
        duplicate_key,
        vec![b' '; ATTESTATION_COLLECTION_MAX_BYTES + 1],
        vec![b' '; APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES + 1],
        vec![valid.clone(); ATTESTATION_COLLECTION_MAX_RECORDS + 1].join(&b'\n'),
    ] {
        assert_eq!(
            select_bundle(&input, |_| panic!("invalid collection reached verifier")),
            Err(BundleSelectionError::InvalidCollection)
        );
    }
}

#[test]
fn limits_accept_exact_boundaries_and_bound_verifier_attempts() {
    let mut padded = fixture();
    padded.resize(APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES, b' ');
    assert_eq!(select_bundle(&padded, verify).unwrap(), padded);
    let collection = vec![fixture(); ATTESTATION_COLLECTION_MAX_RECORDS].join(&b'\n');
    let mut attempts = 0;
    assert_eq!(
        select_bundle(&collection, |_| {
            attempts += 1;
            Err(ReleaseAttestationError::VerificationFailed)
        }),
        Err(BundleSelectionError::NoMatchingBundle)
    );
    assert_eq!(attempts, ATTESTATION_COLLECTION_MAX_RECORDS);
}
