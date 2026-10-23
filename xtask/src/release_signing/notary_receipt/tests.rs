use super::*;

const ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
const SOURCE: &str = "0123456789abcdef0123456789abcdef01234567";

fn context() -> Context {
    Context::new(
        b"exact submitted artifact",
        "x86_64-apple-darwin",
        Some(SOURCE.into()),
    )
    .unwrap()
}

#[test]
fn accepted_requires_successful_command_and_retains_exact_artifact_context() {
    for success in [true, false] {
        let response = format!(r#"{{"id":"{ID}","status":"Accepted"}}"#);
        let (receipt, result) = interpret(response.as_bytes(), success, context());
        assert_eq!(result.is_ok(), success);
        let receipt = receipt.unwrap();
        let value: serde_json::Value =
            serde_json::from_str(receipt.strip_prefix(PREFIX).unwrap()).unwrap();
        assert_eq!(value["submission_id"], ID);
        assert_eq!(value["status"], "Accepted");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["source_commit"], SOURCE);
        assert_eq!(value["target"], "x86_64-apple-darwin");
        assert_eq!(
            value["artifact_sha256"],
            super::super::super::sha256_hex(b"exact submitted artifact")
        );
        assert_eq!(value.as_object().unwrap().len(), 6);
    }
}

#[test]
fn pending_and_rejected_receipts_survive_nonzero_exit_without_granting_success() {
    for status in ["In Progress", "Invalid", "Rejected"] {
        for success in [true, false] {
            let response = format!(r#"{{"id":"{ID}","status":"{status}"}}"#);
            let (receipt, result) = interpret(response.as_bytes(), success, context());
            assert!(result.is_err());
            let receipt = receipt.unwrap();
            assert!(receipt.contains(ID));
            assert!(receipt.contains(status));
        }
    }
}

#[test]
fn valid_submission_id_with_absent_status_retains_unavailable_receipt_and_refuses_success() {
    for success in [true, false] {
        let response = format!(r#"{{"id":"{ID}","message":"secret-canary"}}"#);
        let (receipt, result) = interpret(response.as_bytes(), success, context());
        assert!(result.is_err());
        let receipt = receipt.unwrap();
        assert!(receipt.contains(r#""status":"Unavailable""#));
        assert!(receipt.contains(ID));
        assert!(!receipt.contains("secret-canary"));
    }
}

#[test]
fn provider_account_messages_and_paths_never_escape() {
    let response = format!(
        r#"{{"id":"{ID}","status":"In Progress","message":"secret-canary","account":"secret-canary","path":"/secret-canary"}}"#
    );
    let (receipt, result) = interpret(response.as_bytes(), false, context());
    assert!(result.is_err());
    assert!(!receipt.unwrap().contains("secret-canary"));
    assert!(!result.unwrap_err().contains("secret-canary"));
}

#[test]
fn malformed_unknown_duplicate_oversized_and_secret_bearing_fields_refuse_receipts() {
    for response in [
        br#"{"id":"secret-canary","status":"Accepted"}"#.as_slice(),
        br#"{"status":"Accepted"}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","status":"secret-canary"}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","status":"Unavailable"}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","status":null}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","status":42}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","status":"Accepted","status":"Invalid"}"#,
        br#"{"id":"12345678-90ab-cdef-1234-567890abcdef","id":"12345678-90ab-cdef-1234-567890abcdef","status":"Accepted"}"#,
        b"secret-canary not JSON",
    ] {
        let (receipt, result) = interpret(response, false, context());
        assert!(receipt.is_none());
        assert!(!result.unwrap_err().contains("secret-canary"));
    }
    let oversized = vec![b' '; MAX_RESPONSE_BYTES + 1];
    assert!(interpret(&oversized, false, context()).0.is_none());
}

#[test]
fn source_and_target_context_are_closed_and_optional_local_source_is_omitted() {
    for invalid in [
        "",
        "secret-canary",
        "0123456789ABCDEF0123456789abcdef01234567",
    ] {
        assert!(Context::new(b"artifact", "x86_64-apple-darwin", Some(invalid.into())).is_err());
    }
    assert!(Context::new(b"artifact", "secret-canary", None).is_err());
    let local = Context::new(b"artifact", "aarch64-apple-darwin", None).unwrap();
    let response = format!(r#"{{"id":"{ID}","status":"Accepted"}}"#);
    let (receipt, result) = interpret(response.as_bytes(), true, local);
    assert!(result.is_ok());
    assert!(!receipt.unwrap().contains("source_commit"));
}
