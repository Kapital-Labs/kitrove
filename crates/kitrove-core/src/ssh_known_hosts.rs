use std::path::Path;

use data_encoding::BASE64;
use hmac::{Hmac, KeyInit as _, Mac as _};
use russh::keys::{PublicKey, parse_public_key_base64};
use sha1::Sha1;

use crate::BackendError;
use crate::read_only_fs::{ReadOnlyFileError, read_bounded_regular_file};

const MAX_KNOWN_HOSTS_BYTES: usize = 1024 * 1024;
const MAX_KNOWN_HOSTS_LINE_BYTES: usize = 16 * 1024;
const MAX_KNOWN_HOSTS_ENTRIES: usize = 4096;
const MAX_HOSTS_PER_ENTRY: usize = 32;
const MAX_HOST_PATTERN_BYTES: usize = 1024;
const MAX_KEY_FIELD_BYTES: usize = 12 * 1024;

/// Verifies one SSH server key against a bounded read-only `known_hosts` file.
pub(crate) fn verify_known_host_file(
    path: &Path,
    host: &str,
    port: u16,
    server_key: &PublicKey,
) -> Result<(), BackendError> {
    let bytes =
        read_bounded_regular_file(path, MAX_KNOWN_HOSTS_BYTES).map_err(|error| match error {
            ReadOnlyFileError::Missing => known_hosts_missing(),
            ReadOnlyFileError::Unsafe => known_hosts_unsafe(),
            ReadOnlyFileError::Limit => known_hosts_limit(),
        })?;
    verify_known_host_bytes(&bytes, host, port, server_key)
}

/// Verifies one SSH server key against already-bounded `known_hosts` bytes.
pub(crate) fn verify_known_host_bytes(
    bytes: &[u8],
    host: &str,
    port: u16,
    server_key: &PublicKey,
) -> Result<(), BackendError> {
    if bytes.len() > MAX_KNOWN_HOSTS_BYTES || !host.is_ascii() || host.is_empty() {
        return Err(known_hosts_limit());
    }
    let target = if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    };
    let mut matching_algorithm = None;
    let mut entries = 0usize;

    for raw_line in bytes.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if raw_line.len() > MAX_KNOWN_HOSTS_LINE_BYTES {
            return Err(known_hosts_limit());
        }
        let line = std::str::from_utf8(raw_line).map_err(|_| known_hosts_invalid())?;
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        entries = entries.checked_add(1).ok_or_else(known_hosts_limit)?;
        if entries > MAX_KNOWN_HOSTS_ENTRIES {
            return Err(known_hosts_limit());
        }

        let mut fields = line.split_ascii_whitespace();
        let first = fields.next().ok_or_else(known_hosts_invalid)?;
        let (marker, hosts) = if first.starts_with('@') {
            (Some(first), fields.next().ok_or_else(known_hosts_invalid)?)
        } else {
            (None, first)
        };
        if hosts.len() > MAX_HOST_PATTERN_BYTES {
            return Err(known_hosts_limit());
        }
        let matches_target = host_list_matches(hosts, &target)?;
        if !matches_target {
            continue;
        }
        if marker.is_some() {
            return Err(known_hosts_unsupported());
        }

        let algorithm = fields.next().ok_or_else(known_hosts_invalid)?;
        let encoded_key = fields.next().ok_or_else(known_hosts_invalid)?;
        if algorithm.len() > 128 || encoded_key.len() > MAX_KEY_FIELD_BYTES {
            return Err(known_hosts_limit());
        }
        let recorded = parse_public_key_base64(encoded_key).map_err(|_| known_hosts_invalid())?;
        if algorithm != recorded.algorithm().as_str() {
            return Err(known_hosts_invalid());
        }
        if recorded.algorithm() != server_key.algorithm() {
            continue;
        }
        match &matching_algorithm {
            None => matching_algorithm = Some(recorded),
            Some(existing) if *existing == recorded => {}
            Some(_) => return Err(known_hosts_ambiguous()),
        }
    }

    match matching_algorithm {
        Some(recorded) if recorded == *server_key => Ok(()),
        Some(_) => Err(known_hosts_changed()),
        None => Err(known_hosts_unknown()),
    }
}

fn host_list_matches(hosts: &str, target: &str) -> Result<bool, BackendError> {
    let mut count = 0usize;
    let mut matched = false;
    for pattern in hosts.split(',') {
        count = count.checked_add(1).ok_or_else(known_hosts_limit)?;
        if count > MAX_HOSTS_PER_ENTRY || pattern.is_empty() {
            return Err(known_hosts_limit());
        }
        if pattern.starts_with("|1|") {
            matched |= hashed_host_matches(pattern, target)?;
        } else if pattern.contains(['*', '?', '!', '\\']) {
            if pattern == target {
                return Err(known_hosts_unsupported());
            }
        } else {
            matched |= pattern == target;
        }
    }
    Ok(matched)
}

fn hashed_host_matches(pattern: &str, target: &str) -> Result<bool, BackendError> {
    let mut parts = pattern.split('|');
    if parts.next() != Some("") || parts.next() != Some("1") {
        return Err(known_hosts_invalid());
    }
    let salt = parts.next().ok_or_else(known_hosts_invalid)?;
    let expected = parts.next().ok_or_else(known_hosts_invalid)?;
    if parts.next().is_some() || salt.len() > 256 || expected.len() > 256 {
        return Err(known_hosts_invalid());
    }
    let salt = BASE64
        .decode(salt.as_bytes())
        .map_err(|_| known_hosts_invalid())?;
    let expected = BASE64
        .decode(expected.as_bytes())
        .map_err(|_| known_hosts_invalid())?;
    if salt.is_empty() || salt.len() > 64 || expected.len() != 20 {
        return Err(known_hosts_invalid());
    }
    let mac = Hmac::<Sha1>::new_from_slice(&salt).map_err(|_| known_hosts_invalid())?;
    Ok(mac
        .chain_update(target.as_bytes())
        .verify_slice(&expected)
        .is_ok())
}

const fn known_hosts_limit() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_limit",
        "SSH host verification input exceeds a supported limit",
    )
}

const fn known_hosts_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_invalid",
        "SSH host verification input is invalid",
    )
}

const fn known_hosts_unsupported() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_unsupported",
        "SSH host verification entry uses an unsupported policy",
    )
}

const fn known_hosts_ambiguous() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_ambiguous",
        "SSH host verification authority is ambiguous",
    )
}

const fn known_hosts_changed() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_host_key_changed",
        "SSH host key does not match machine-local authority",
    )
}

const fn known_hosts_unknown() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_host_unknown",
        "SSH host is not present in machine-local authority",
    )
}

const fn known_hosts_missing() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_missing",
        "SSH host verification authority is missing",
    )
}

const fn known_hosts_unsafe() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_known_hosts_unsafe",
        "SSH host verification authority is unsafe",
    )
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use russh::keys::parse_public_key_base64;
    use sha1::Sha1;

    use super::verify_known_host_bytes;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const OTHER_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

    #[test]
    fn exact_port_and_hashed_entries_verify_the_same_key() {
        let key = parse_public_key_base64(KEY).unwrap();
        let exact = format!("example.com ssh-ed25519 {KEY}\n");
        verify_known_host_bytes(exact.as_bytes(), "example.com", 22, &key).unwrap();

        let port = format!("[example.com]:2222 ssh-ed25519 {KEY} comment\n");
        verify_known_host_bytes(port.as_bytes(), "example.com", 2222, &key).unwrap();

        let salt = b"bounded-known-host-salt";
        let digest = Hmac::<Sha1>::new_from_slice(salt)
            .unwrap()
            .chain_update(b"example.com")
            .finalize()
            .into_bytes();
        let hashed = format!(
            "|1|{}|{} ssh-ed25519 {KEY}\n",
            BASE64.encode(salt),
            BASE64.encode(&digest)
        );
        verify_known_host_bytes(hashed.as_bytes(), "example.com", 22, &key).unwrap();
    }

    #[test]
    fn changed_unknown_ambiguous_and_marked_authority_fail_closed() {
        let key = parse_public_key_base64(KEY).unwrap();
        let changed = format!("example.com ssh-ed25519 {OTHER_KEY}\n");
        assert_eq!(
            verify_known_host_bytes(changed.as_bytes(), "example.com", 22, &key)
                .unwrap_err()
                .code(),
            "sync_backend.ssh_host_key_changed"
        );
        assert_eq!(
            verify_known_host_bytes(changed.as_bytes(), "other.example.com", 22, &key)
                .unwrap_err()
                .code(),
            "sync_backend.ssh_host_unknown"
        );

        let ambiguous =
            format!("example.com ssh-ed25519 {KEY}\nexample.com ssh-ed25519 {OTHER_KEY}\n");
        assert_eq!(
            verify_known_host_bytes(ambiguous.as_bytes(), "example.com", 22, &key)
                .unwrap_err()
                .code(),
            "sync_backend.ssh_known_hosts_ambiguous"
        );
        let revoked = format!("@revoked example.com ssh-ed25519 {KEY}\n");
        assert!(verify_known_host_bytes(revoked.as_bytes(), "example.com", 22, &key).is_err());

        let duplicate = format!("example.com ssh-ed25519 {KEY}\nexample.com ssh-ed25519 {KEY}\n");
        verify_known_host_bytes(duplicate.as_bytes(), "example.com", 22, &key).unwrap();
    }

    #[test]
    fn malformed_oversized_and_unsupported_target_entries_are_rejected() {
        let key = parse_public_key_base64(KEY).unwrap();
        for input in [
            b"example.com\n".as_slice(),
            b"example.com ssh-ed25519 invalid-base64\n".as_slice(),
            b"*.example.com ssh-ed25519 invalid-base64\n".as_slice(),
            b"example.com ssh-rsa AAAA\n".as_slice(),
            b"\xff\n".as_slice(),
        ] {
            assert!(verify_known_host_bytes(input, "example.com", 22, &key).is_err());
        }
        assert!(
            verify_known_host_bytes(&vec![b'a'; 1024 * 1024 + 1], "example.com", 22, &key).is_err()
        );
    }

    #[test]
    fn unrelated_records_do_not_supply_or_corrupt_target_authority() {
        let key = parse_public_key_base64(KEY).unwrap();
        let input = format!(
            "other.example.com ssh-ed25519 invalid-base64\nexample.com ssh-ed25519 {KEY}\n"
        );
        verify_known_host_bytes(input.as_bytes(), "example.com", 22, &key).unwrap();
    }
}
