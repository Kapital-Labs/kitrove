use std::fmt::{self, Debug, Formatter};

use kitrove_model::RemoteKey;
use url::{Host, Url};

use crate::BackendError;

const MAX_REMOTE_URL_BYTES: usize = 4096;
const MAX_SSH_USERNAME_BYTES: usize = 64;
const DEFAULT_SSH_PORT: u16 = 22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitSshService {
    UploadPack,
    ReceivePack,
}

impl GitSshService {
    const fn command(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

/// One canonical credential-free HTTPS Git remote identity.
#[derive(Clone, Eq, PartialEq)]
pub struct GitRemoteUrl {
    url: Url,
    origin: String,
    remote_key: RemoteKey,
}

impl GitRemoteUrl {
    /// Parses the deliberately narrow canonical HTTPS remote URL grammar.
    pub fn parse(input: &str) -> Result<Self, BackendError> {
        if !common_input_valid(input) {
            return Err(https_url_invalid());
        }
        let url = Url::parse(input).map_err(|_| https_url_invalid())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
            || url.as_str() != input
        {
            return Err(https_url_invalid());
        }
        let Host::Domain(host) = url.host().ok_or_else(https_url_invalid)? else {
            return Err(https_url_invalid());
        };
        if !valid_canonical_host(host) || !valid_remote_path(url.path(), true) {
            return Err(https_url_invalid());
        }
        let origin = format!("https://{host}");
        let remote_key = remote_key(b"kitrove-git-sync-remote-v1\0", input, https_url_invalid)?;
        Ok(Self {
            url,
            origin,
            remote_key,
        })
    }

    /// Returns the stable redacted synchronization identity.
    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }

    pub(crate) fn service_url(
        &self,
        suffix: &str,
        query: Option<&str>,
    ) -> Result<Url, BackendError> {
        let mut value = self.url.as_str().to_owned();
        value.push_str(suffix);
        if let Some(query) = query {
            value.push('?');
            value.push_str(query);
        }
        Url::parse(&value).map_err(|_| https_url_invalid())
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    pub(crate) fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

impl Debug for GitRemoteUrl {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRemoteUrl")
            .field("remote_key", &self.remote_key)
            .finish_non_exhaustive()
    }
}

/// One canonical credential-free SSH Git remote identity.
#[derive(Clone, Eq, PartialEq)]
pub struct SshGitRemoteUrl {
    username: Option<String>,
    host: String,
    port: u16,
    repository_path: String,
    remote_key: RemoteKey,
}

impl SshGitRemoteUrl {
    /// Parses the deliberately narrow canonical SSH remote URL grammar.
    pub fn parse(input: &str) -> Result<Self, BackendError> {
        if !common_input_valid(input) || input.contains('~') {
            return Err(ssh_url_invalid());
        }
        let url = Url::parse(input).map_err(|_| ssh_url_invalid())?;
        let authority = input
            .strip_prefix("ssh://")
            .and_then(|rest| rest.split('/').next())
            .ok_or_else(ssh_url_invalid)?;
        if url.scheme() != "ssh"
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || matches!(url.port(), Some(0 | DEFAULT_SSH_PORT))
            || (authority.starts_with('@') && url.username().is_empty())
            || url.as_str() != input
        {
            return Err(ssh_url_invalid());
        }
        let Host::Domain(host) = url.host().ok_or_else(ssh_url_invalid)? else {
            return Err(ssh_url_invalid());
        };
        if !valid_canonical_host(host) || !valid_remote_path(url.path(), false) {
            return Err(ssh_url_invalid());
        }
        let username = match url.username() {
            "" => None,
            value if valid_ssh_username(value) => Some(value.to_owned()),
            _ => return Err(ssh_url_invalid()),
        };
        let port = url.port().unwrap_or(DEFAULT_SSH_PORT);
        let repository_path = url.path().to_owned();
        let remote_key = remote_key(b"kitrove-git-ssh-remote-v1\0", input, ssh_url_invalid)?;
        Ok(Self {
            username,
            host: host.to_owned(),
            port,
            repository_path,
            remote_key,
        })
    }

    /// Returns the stable redacted synchronization identity.
    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }

    pub(crate) fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn service_command(&self, service: GitSshService) -> String {
        format!("{} '{}'", service.command(), self.repository_path)
    }

    #[cfg(test)]
    fn repository_path(&self) -> &str {
        &self.repository_path
    }
}

impl Debug for SshGitRemoteUrl {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshGitRemoteUrl")
            .field("remote_key", &self.remote_key)
            .finish_non_exhaustive()
    }
}

fn common_input_valid(input: &str) -> bool {
    input.len() <= MAX_REMOTE_URL_BYTES
        && input.is_ascii()
        && !input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && !input.contains(['%', '\\'])
}

fn valid_canonical_host(host: &str) -> bool {
    !host.is_empty()
        && !host.ends_with('.')
        && host == host.to_ascii_lowercase()
        && !host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && valid_dns_name(host)
}

fn valid_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_remote_path(path: &str, allow_tilde: bool) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && path.split('/').skip(1).all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b'-')
                        || (allow_tilde && byte == b'~')
                })
        })
}

fn valid_ssh_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_SSH_USERNAME_BYTES
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn remote_key(
    domain: &[u8],
    input: &str,
    invalid: fn() -> BackendError,
) -> Result<RemoteKey, BackendError> {
    let digest = blake3::hash([domain, input.as_bytes()].concat().as_slice());
    RemoteKey::parse(format!("remote:blake3:{}", digest.to_hex())).map_err(|_| invalid())
}

const fn https_url_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.git_url_invalid",
        "Git remote URL is not canonical supported HTTPS authority",
    )
}

const fn ssh_url_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.git_ssh_url_invalid",
        "Git remote URL is not canonical supported SSH authority",
    )
}

#[cfg(test)]
mod tests {
    use super::{GitRemoteUrl, GitSshService, SshGitRemoteUrl};

    #[test]
    fn https_remote_preserves_the_existing_canonical_contract() {
        let accepted = GitRemoteUrl::parse("https://example.com/owner/repo.git").unwrap();
        assert_eq!(accepted.origin(), "https://example.com");
        assert_eq!(
            accepted
                .service_url("/info/refs", Some("service=git-upload-pack"))
                .unwrap()
                .as_str(),
            "https://example.com/owner/repo.git/info/refs?service=git-upload-pack"
        );
        assert!(!format!("{accepted:?}").contains("example.com"));

        for rejected in [
            "http://example.com/owner/repo",
            "https://EXAMPLE.com/owner/repo",
            "https://example.com:443/owner/repo",
            "https://user@example.com/owner/repo",
            "https://127.0.0.1/owner/repo",
            "https://example.com/owner//repo",
            "https://example.com/owner/../repo",
            "https://example.com/owner/%2e/repo",
            "https://example.com/owner/repo/",
            "https://example.com/owner/repo?x=1",
            "https://example.com/owner/repo#fragment",
        ] {
            assert!(
                GitRemoteUrl::parse(rejected).is_err(),
                "accepted {rejected}"
            );
        }
        assert!(GitRemoteUrl::parse(&format!("https://example.com/{}", "a".repeat(4096))).is_err());
    }

    #[test]
    fn ssh_remote_accepts_only_exact_canonical_dns_forms() {
        let default = SshGitRemoteUrl::parse("ssh://git@example.com/owner/repo.git").unwrap();
        assert_eq!(default.username(), Some("git"));
        assert_eq!(default.host(), "example.com");
        assert_eq!(default.port(), 22);
        assert_eq!(default.repository_path(), "/owner/repo.git");
        assert_eq!(
            default.service_command(GitSshService::UploadPack),
            "git-upload-pack '/owner/repo.git'"
        );
        assert_eq!(
            default.service_command(GitSshService::ReceivePack),
            "git-receive-pack '/owner/repo.git'"
        );
        assert!(!format!("{default:?}").contains("example.com"));

        let port = SshGitRemoteUrl::parse("ssh://example.com:2222/owner/repo.git").unwrap();
        assert_eq!(port.username(), None);
        assert_eq!(port.port(), 2222);

        for rejected in [
            "git@example.com:owner/repo.git",
            "ssh://@example.com/owner/repo.git",
            "ssh://git:secret@example.com/owner/repo.git",
            "ssh://git@@example.com/owner/repo.git",
            "ssh://EXAMPLE.com/owner/repo.git",
            "ssh://example.com:22/owner/repo.git",
            "ssh://127.0.0.1/owner/repo.git",
            "ssh://[::1]/owner/repo.git",
            "ssh://example.com/~owner/repo.git",
            "ssh://example.com/owner//repo.git",
            "ssh://example.com/owner/../repo.git",
            "ssh://example.com/owner/%2e/repo.git",
            "ssh://example.com/owner/repo.git/",
            "ssh://example.com/owner/repo.git?x=1",
            "ssh://example.com/owner/repo.git#fragment",
            "ssh://bad:user@example.com/owner/repo.git",
            "ssh://example.com/owner/repo'git",
            "ssh://example.com/owner/repo\\git",
            "ssh://example.com/owner/repo git",
        ] {
            assert!(
                SshGitRemoteUrl::parse(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    #[test]
    fn transport_kinds_have_domain_separated_remote_keys() {
        let https = GitRemoteUrl::parse("https://example.com/owner/repo.git").unwrap();
        let ssh = SshGitRemoteUrl::parse("ssh://example.com/owner/repo.git").unwrap();
        assert_ne!(https.remote_key(), ssh.remote_key());
    }

    #[test]
    fn ssh_remote_errors_and_debug_are_structurally_redacted() {
        let canary = "SSH_REMOTE_SECRET_CANARY";
        let error =
            SshGitRemoteUrl::parse(&format!("ssh://example.com/owner/{canary}'")).unwrap_err();
        assert!(!format!("{error}").contains(canary));
        assert!(!format!("{error:?}").contains(canary));

        let accepted = SshGitRemoteUrl::parse("ssh://example.com/owner/repo.git").unwrap();
        assert!(!format!("{accepted:?}").contains("owner"));
        assert!(
            SshGitRemoteUrl::parse(&format!("ssh://example.com/{}", "a".repeat(4096))).is_err()
        );
    }
}
