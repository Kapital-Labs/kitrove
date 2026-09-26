//! Shared native signature policy, not a verifier or execution authorization.
//! Callers must run the trusted native verifier against retained, authenticated
//! bytes and revalidate their identity afterward. These rules launch nothing.

/// Upper bound shared by captured signature parsing and native CMS inspection.
pub const APPLE_SIGNATURE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Public Security.framework hardened-runtime code-signing flag.
pub const APPLE_HARDENED_RUNTIME_FLAG: u32 = 0x10000;

/// A claimed identity from bounded codesign display output, never execution trust.
/// The fixed system verifier must dynamically validate this exact requirement
/// against the retained process before the caller can rely on the identity.
#[derive(Clone, Eq, PartialEq)]
pub struct AppleProcessIdentityCandidate {
    cdhash: String,
}

impl AppleProcessIdentityCandidate {
    /// Capture exactly one canonical CDHash field. Display output is untrusted.
    pub fn from_display(detail: &[u8]) -> Result<Self, &'static str> {
        const INVALID: &str = "invalid Apple process identity detail";
        if detail.len() > 4096 || detail.contains(&0) {
            return Err(INVALID);
        }
        let detail = std::str::from_utf8(detail).map_err(|_| INVALID)?;
        let mut hashes = detail
            .lines()
            .filter_map(|line| line.strip_prefix("CDHash="));
        let cdhash = hashes.next().ok_or(INVALID)?;
        if hashes.next().is_some()
            || cdhash.len() != 40
            || !cdhash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(INVALID);
        }
        Ok(Self {
            cdhash: cdhash.to_owned(),
        })
    }

    /// An inline native requirement with no caller-provided syntax or policy flags.
    /// Matching it proves neither provenance nor the initial verifier's trust.
    pub fn exact_requirement(&self) -> String {
        format!("=cdhash H\"{}\"", self.cdhash)
    }
}

/// Inline requirement for a Developer ID signature from the reviewed Apple team.
pub const APPLE_REQUIREMENT: &str = concat!(
    "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists ",
    "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists ",
    "and certificate leaf[subject.OU] = \"98RZ36ES7A\""
);

/// Operator verification script. The caller supplies the selected file and reviewed
/// publisher through the named environment variables; no credentials are consumed.
/// Consumer use must pin the publisher independently, not trust ambient configuration.
pub const WINDOWS_VERIFY: &str = r#"
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $env:KITROVE_VERIFY_FILE
if ($signature.Status -ne 'Valid' -or
    $signature.SignatureType -ne 'Authenticode' -or
    $null -eq $signature.SignerCertificate -or
    $null -eq $signature.TimeStamperCertificate -or
    $signature.SignerCertificate.Subject -cne $env:KITROVE_WINDOWS_PUBLISHER) {
    throw 'Expected timestamped publisher signature is absent or invalid'
}
"#;

/// Check supplementary codesign inspection output after native signature verification.
/// Text alone is never signature proof. Containers need a timestamp; executables
/// additionally need hardened runtime. This preserves the existing publisher policy.
pub fn validate_apple_signature_detail(
    detail: &[u8],
    executable: bool,
) -> Result<(), &'static str> {
    let detail = String::from_utf8_lossy(detail);
    if !detail
        .lines()
        .any(|line| line.starts_with("Timestamp=") && line.len() > 10)
    {
        return Err("Apple signature lacks secure timestamp");
    }
    if executable
        && !detail
            .lines()
            .any(|line| line.starts_with("CodeDirectory ") && line.contains("(runtime)"))
    {
        return Err("Apple signature lacks hardened runtime or secure timestamp");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_candidate_is_exact_bounded_and_not_a_policy_override() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let output = format!("Executable=/private/example\nCDHash={hash}\n");
        let candidate = AppleProcessIdentityCandidate::from_display(output.as_bytes()).unwrap();
        assert_eq!(
            candidate.exact_requirement(),
            format!("=cdhash H\"{hash}\"")
        );
        assert!(
            AppleProcessIdentityCandidate::from_display(output.replace('\n', "\r\n").as_bytes())
                .is_ok()
        );
        for invalid in [
            String::new(),
            format!("CandidateCDHash sha256={hash}\n"),
            format!(" CDHash={hash}\n"),
            format!("CDHash={hash}\nCDHash={hash}\n"),
            format!("CDHash={hash} or anchor apple\n"),
            format!("CDHash={}\n", hash.to_uppercase()),
            format!("CDHash={}\n", &hash[..39]),
            format!("CDHash={hash}0\n"),
            format!("CDHash={hash}\0"),
        ] {
            assert!(AppleProcessIdentityCandidate::from_display(invalid.as_bytes()).is_err());
        }
        assert!(AppleProcessIdentityCandidate::from_display(&[0xff]).is_err());
        let mut maximum = format!("CDHash={hash}\n").into_bytes();
        maximum.resize(4096, b'x');
        assert!(AppleProcessIdentityCandidate::from_display(&maximum).is_ok());
        maximum.push(b'x');
        assert!(AppleProcessIdentityCandidate::from_display(&maximum).is_err());
    }

    #[test]
    fn apple_requirement_pins_developer_id_team() {
        assert!(APPLE_REQUIREMENT.starts_with("=anchor apple generic"));
        assert!(APPLE_REQUIREMENT.contains("certificate leaf[subject.OU] = \"98RZ36ES7A\""));
        assert!(APPLE_REQUIREMENT.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(
            APPLE_REQUIREMENT.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists")
        );
    }

    #[test]
    fn apple_executable_requires_timestamp_and_runtime() {
        let valid = b"CodeDirectory v=20500 flags=0x10000(runtime)\nTimestamp=Sep 8, 2026\n";
        assert!(validate_apple_signature_detail(valid, true).is_ok());
        for invalid in [
            b"".as_slice(),
            b"Timestamp=now\n",
            b"CodeDirectory flags=0x10000(runtime)\n",
            b"CodeDirectory flags=0x10000(runtime)\nTimestamp=\n",
        ] {
            assert!(validate_apple_signature_detail(invalid, true).is_err());
        }
    }

    #[test]
    fn container_requires_timestamp_but_not_runtime() {
        assert!(validate_apple_signature_detail(b"Timestamp=now\r\n", false).is_ok());
        for invalid in [b"".as_slice(), b"Timestamp=\n", b"Timestamp=\r\n"] {
            assert!(validate_apple_signature_detail(invalid, false).is_err());
        }
    }
}
