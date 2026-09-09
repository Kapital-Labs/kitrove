#![forbid(unsafe_code)]
//! Pure, value-redacting credential-shape detection shared by authority boundaries.

/// Returns whether a value has the shape of a commonly issued provider credential.
///
/// This deliberately favors false positives over allowing a likely live credential into portable
/// state. Callers must not include the candidate value in diagnostics.
#[must_use]
pub fn is_credential_shaped(value: &str) -> bool {
    let value = value.trim_matches(|character: char| !character.is_ascii_alphanumeric());
    let prefixed_minimums = [
        ("sk-ant-", 20),
        ("sk-live-", 20),
        ("sk_live_", 20),
        ("rk_live_", 20),
        ("github_pat_", 24),
        ("ghp_", 20),
        ("gho_", 20),
        ("ghu_", 20),
        ("ghs_", 20),
        ("ghr_", 20),
        ("npm_", 20),
        ("xoxb-", 25),
        ("xoxp-", 25),
    ];
    prefixed_minimums
        .iter()
        .any(|(prefix, minimum)| value.starts_with(prefix) && value.len() >= *minimum)
        || (value.starts_with("AKIA")
            && value.len() == 20
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
        || (value.starts_with("AIza") && value.len() >= 30)
        || (value.starts_with("sk-") && value.len() >= 20)
}

/// Finds a credential-shaped token in arbitrary bytes without retaining the matched token.
#[must_use]
pub fn contains_credential_shaped_bytes(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'_' | b'-'))
        .filter_map(|candidate| std::str::from_utf8(candidate).ok())
        .any(is_credential_shaped)
}

/// Finds a credential-shaped token in UTF-8 text without retaining the matched token.
#[must_use]
pub fn contains_credential_shaped_text(text: &str) -> bool {
    contains_credential_shaped_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_supported_credential_families_without_matching_normal_prose() {
        for value in [
            "sk-ant-12345678901234567890",
            "github_pat_123456789012345678901234",
            "AKIA1234567890123456",
            "AIza123456789012345678901234567890",
        ] {
            assert!(is_credential_shaped(value), "missed credential family");
        }
        for value in [
            "credential",
            "sk-short",
            "AKIA-not-a-key",
            "company_mcp_token",
        ] {
            assert!(!is_credential_shaped(value), "matched normal identifier");
        }
    }

    #[test]
    fn byte_and_text_tokenizers_share_the_same_boundary() {
        let value = b"before/sk-live-12345678901234567890;after";
        assert!(contains_credential_shaped_bytes(value));
        assert!(contains_credential_shaped_text(
            "before `sk-live-12345678901234567890`; after"
        ));
        assert!(!contains_credential_shaped_text(
            "Ask before accessing credentials or private keys."
        ));
    }
}
