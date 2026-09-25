//! Low-level Apple inspection only. No installer readiness or launch authority.
//! Native calls may block: consumer integration must use ADR-0045's bounded helper.
#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;
use kitrove_release_policy::apple_code_directory::AppleSignatureCandidate;
use kitrove_release_policy::native_signature::{
    APPLE_HARDENED_RUNTIME_FLAG, APPLE_REQUIREMENT, APPLE_SIGNATURE_MAX_BYTES,
};
use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
use sha2::{Digest as _, Sha256};
use std::path::Path;

mod protocol;
pub use protocol::{MAX_INSPECTION_REQUEST_BYTES, encode_inspection_request, inspect_request};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoCMS: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
    static kSecCodeInfoTimestamp: CFStringRef;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureRefused;

impl std::fmt::Display for SignatureRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native Apple signature inspection refused")
    }
}
impl std::error::Error for SignatureRefused {}

/// Validate the fixed publisher policy and compare captured signature fingerprints.
/// Success is low-level evidence only. It does not prove retained path identity,
/// helper cleanup, notarization, executable publication or safe launch.
pub fn inspect_captured_signature(
    path: &Path,
    candidate: &AppleSignatureCandidate,
) -> Result<(), SignatureRefused> {
    inspect_fingerprints(path, candidate.cdhash(), candidate.cms_sha256())
}

fn inspect_fingerprints(
    path: &Path,
    cdhash: &[u8; 20],
    cms_sha256: &[u8; 32],
) -> Result<(), SignatureRefused> {
    if !path.is_absolute() {
        return Err(SignatureRefused);
    }
    let url = CFURL::from_path(path, false).ok_or(SignatureRefused)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| SignatureRefused)?;
    let requirement: SecRequirement = APPLE_REQUIREMENT
        .strip_prefix('=')
        .ok_or(SignatureRefused)?
        .parse()
        .map_err(|_| SignatureRefused)?;
    code.check_validity(Flags::STRICT_VALIDATE, &requirement)
        .map_err(|_| SignatureRefused)?;
    let fields = signing_information(&code)?;
    validate_fields(&fields, cdhash, cms_sha256)
}

fn signing_information(
    code: &SecStaticCode,
) -> Result<CFDictionary<CFString, CFType>, SignatureRefused> {
    let mut output = std::ptr::null();
    // SAFETY: code is a live retained SecStaticCode; output is initialized writable
    // storage. Public flag kSecCSSigningInformation = 1 << 1 requests no internal data.
    let status = unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 1 << 1, &mut output) };
    if status != 0 || output.is_null() {
        return Err(SignatureRefused);
    }
    // SAFETY: successful Copy returns an owned CFDictionary with CFString keys and
    // CFType values. The wrapper releases it exactly once; each value is downcast below.
    Ok(unsafe { CFDictionary::wrap_under_create_rule(output) })
}

fn validate_fields(
    fields: &CFDictionary<CFString, CFType>,
    cdhash: &[u8; 20],
    cms_sha256: &[u8; 32],
) -> Result<(), SignatureRefused> {
    // SAFETY: these are documented immutable exported Security.framework CFString
    // constants. Retain using the get rule; reject null before wrapping.
    let keys = unsafe {
        [
            kSecCodeInfoUnique,
            kSecCodeInfoCMS,
            kSecCodeInfoFlags,
            kSecCodeInfoTimestamp,
        ]
    };
    let mut values = Vec::with_capacity(keys.len());
    for key in keys {
        if key.is_null() {
            return Err(SignatureRefused);
        }
        // SAFETY: non-null framework-owned immutable CFString, retained by this wrapper.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        values.push(fields.find(&key).ok_or(SignatureRefused)?.clone());
    }
    let directory = values[0].downcast::<CFData>().ok_or(SignatureRefused)?;
    let cms = values[1].downcast::<CFData>().ok_or(SignatureRefused)?;
    let flags = values[2]
        .downcast::<CFNumber>()
        .and_then(|n| n.to_i64())
        .ok_or(SignatureRefused)?;
    let timestamp = values[3].downcast::<CFDate>().ok_or(SignatureRefused)?;
    if directory.bytes() != cdhash
        || cms.bytes().is_empty()
        || cms.bytes().len() > APPLE_SIGNATURE_MAX_BYTES
        || Sha256::digest(cms.bytes()).as_slice() != cms_sha256
        || u32::try_from(flags).is_err()
        || flags & i64::from(APPLE_HARDENED_RUNTIME_FLAG) == 0
        || !timestamp.abs_time().is_finite()
    {
        return Err(SignatureRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_values() -> [CFType; 4] {
        [
            CFData::from_buffer(&[7; 20]).as_CFType(),
            CFData::from_buffer(b"captured CMS").as_CFType(),
            CFNumber::from(0x10000i64).as_CFType(),
            CFDate::new(42.0).as_CFType(),
        ]
    }

    fn dictionary(values: &[CFType]) -> CFDictionary<CFString, CFType> {
        // SAFETY: immutable public framework keys, retained with the get rule.
        let keys = unsafe {
            [
                kSecCodeInfoUnique,
                kSecCodeInfoCMS,
                kSecCodeInfoFlags,
                kSecCodeInfoTimestamp,
            ]
            .map(|key| CFString::wrap_under_get_rule(key))
        };
        let pairs: Vec<_> = keys.into_iter().zip(values.iter().cloned()).collect();
        CFDictionary::from_CFType_pairs(&pairs)
    }

    #[test]
    fn typed_dictionary_comparison_is_not_signature_authentication() {
        let digest: [u8; 32] = Sha256::digest(b"captured CMS").into();
        assert!(validate_fields(&dictionary(&valid_values()), &[7; 20], &digest).is_ok());
        assert!(validate_fields(&dictionary(&valid_values()), &[8; 20], &digest).is_err());
        assert!(validate_fields(&dictionary(&valid_values()), &[7; 20], &[0; 32]).is_err());
    }

    #[test]
    fn missing_wrong_typed_and_policy_fields_fail_closed() {
        let digest: [u8; 32] = Sha256::digest(b"captured CMS").into();
        for count in 0..4 {
            assert!(
                validate_fields(&dictionary(&valid_values()[..count]), &[7; 20], &digest).is_err()
            );
        }
        for index in 0..4 {
            let mut values = valid_values();
            values[index] = CFString::new("wrong type").as_CFType();
            assert!(validate_fields(&dictionary(&values), &[7; 20], &digest).is_err());
        }
        for (index, value) in [
            (0, CFData::from_buffer(&[7; 19]).as_CFType()),
            (1, CFData::from_buffer(b"").as_CFType()),
            (2, CFNumber::from(0i64).as_CFType()),
            (2, CFNumber::from(-1i64).as_CFType()),
            (
                2,
                CFNumber::from(i64::from(u32::MAX) + 1 + 0x10000).as_CFType(),
            ),
            (3, CFDate::new(f64::NAN).as_CFType()),
        ] {
            let mut values = valid_values();
            values[index] = value;
            assert!(validate_fields(&dictionary(&values), &[7; 20], &digest).is_err());
        }
    }
}
