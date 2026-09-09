use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gix_hash::{Kind as HashKind, ObjectId};
use gix_object::{CommitRef, Kind as ObjectKind, TreeRefIter};
use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, NativeSkillObject, StoredSkillTree, hash_tree,
};
use kitrove_model::{
    ObjectDescriptor, PortablePath, PublicationId, RemoteKey, RemoteRevision, SnapshotDigest,
    SnapshotObjectKind, SyncLimits,
};
use serde::{Deserialize, Serialize};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use zeroize::{Zeroize as _, Zeroizing};

use crate::git_remote::GitRemoteUrl;
use crate::sync_backend::{sealed::Sealed, validate_descriptor_budget};
use crate::{
    BackendError, PortableSnapshotV1, PublicationIntent, PublicationStatus, RemoteSnapshot,
    SyncBackend, SyncBackendApply, SyncBackendRead, VerifiedObjectEnvelope, VerifiedRemoteHistory,
    sync_backend::VerifiedDocumentObject,
};

#[path = "ssh_git_sync_backend.rs"]
mod ssh_backend;
pub use ssh_backend::{SshGitApplySession, SshGitReadSession, SshGitSyncBackend};

const FIXED_REF: &[u8] = b"refs/heads/kitrove-sync-v1";
const ABSENT_OID: &[u8; 40] = b"0000000000000000000000000000000000000000";
pub(crate) const MAX_PACKET_LINE_BYTES: usize = 65_520;
const USER_AGENT: &str = "kitrove-git-sync/1";
const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_REALM_BYTES: usize = 256;

/// One bounded in-memory Basic credential with no rendering or persistence surface.
pub struct GitBasicCredential {
    username: Zeroizing<String>,
    token: Zeroizing<String>,
}

impl GitBasicCredential {
    /// Constructs one operation-local credential from explicitly supplied values.
    pub fn new(username: String, token: String) -> Result<Self, BackendError> {
        let username = Zeroizing::new(username);
        let token = Zeroizing::new(token);
        if username.is_empty()
            || token.is_empty()
            || username.len() > MAX_CREDENTIAL_BYTES
            || token.len() > MAX_CREDENTIAL_BYTES
            || username
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b':')
            || token.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(authentication_failed());
        }
        Ok(Self { username, token })
    }
}

/// A sealed callback boundary for obtaining one credential during one operation.
pub struct GitCredentialProvider {
    source: Box<dyn Fn() -> Option<GitBasicCredential> + Send + Sync>,
}

impl GitCredentialProvider {
    /// Wraps an explicitly selected operation-local source owned by the composition root.
    pub fn operation_local(
        source: impl Fn() -> Option<GitBasicCredential> + Send + Sync + 'static,
    ) -> Self {
        Self {
            source: Box::new(source),
        }
    }

    /// Wraps a terminal-only prompt owned by the CLI composition root.
    pub fn terminal(
        prompt: impl Fn() -> Option<GitBasicCredential> + Send + Sync + 'static,
    ) -> Self {
        Self::operation_local(prompt)
    }
}

struct GitAuthentication<'a> {
    provider: Option<&'a GitCredentialProvider>,
    header: Option<Zeroizing<String>>,
    challenged: bool,
}

impl<'a> GitAuthentication<'a> {
    const fn new(provider: Option<&'a GitCredentialProvider>) -> Self {
        Self {
            provider,
            header: None,
            challenged: false,
        }
    }
}

struct GitBudget {
    remaining_response_bytes: u64,
    remaining_packet_lines: usize,
    remaining_advertised_refs: usize,
    remaining_decoded_objects: usize,
    remaining_decoded_bytes: u64,
}

impl GitBudget {
    const fn new(limits: SyncLimits) -> Self {
        let git = limits.git();
        Self {
            remaining_response_bytes: git.max_response_body_bytes(),
            remaining_packet_lines: git.max_packet_lines(),
            remaining_advertised_refs: git.max_advertisement_refs(),
            remaining_decoded_objects: git.max_decoded_objects(),
            remaining_decoded_bytes: git.max_total_decoded_object_bytes(),
        }
    }

    fn charge_response(&mut self, bytes: u64) -> Result<(), BackendError> {
        self.remaining_response_bytes = self
            .remaining_response_bytes
            .checked_sub(bytes)
            .ok_or_else(limit_exceeded)?;
        Ok(())
    }

    fn charge_object(&mut self, bytes: u64) -> Result<(), BackendError> {
        let remaining_objects = self
            .remaining_decoded_objects
            .checked_sub(1)
            .ok_or_else(limit_exceeded)?;
        let remaining_bytes = self
            .remaining_decoded_bytes
            .checked_sub(bytes)
            .ok_or_else(limit_exceeded)?;
        self.remaining_decoded_objects = remaining_objects;
        self.remaining_decoded_bytes = remaining_bytes;
        Ok(())
    }
}

struct GitOperationDeadline {
    expires: Instant,
}

impl GitOperationDeadline {
    fn new(limits: SyncLimits) -> Result<Self, BackendError> {
        let duration = Duration::from_millis(limits.git().operation_deadline_ms());
        let expires = Instant::now()
            .checked_add(duration)
            .ok_or_else(limit_exceeded)?;
        Ok(Self { expires })
    }

    fn remaining(&self) -> Result<Duration, BackendError> {
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(transport_failed)
    }
}

#[derive(Clone)]
struct GitObject {
    kind: ObjectKind,
    data: Vec<u8>,
}

type GitObjectMap = BTreeMap<ObjectId, GitObject>;

struct FetchedGit {
    objects: GitObjectMap,
    shallow: BTreeSet<ObjectId>,
}

#[cfg(test)]
struct VerifiedGitSnapshot {
    snapshot: PortableSnapshotV1,
    objects: BTreeMap<PortablePath, VerifiedObjectEnvelope>,
    history: Vec<ObjectId>,
}

struct VerifiedGitHistory {
    snapshots: Vec<(RemoteRevision, Arc<PortableSnapshotV1>)>,
    objects: BTreeMap<PortablePath, VerifiedObjectEnvelope>,
    commits: Vec<ObjectId>,
}

struct GitObservation {
    remote: RemoteSnapshot,
    objects: BTreeMap<PortablePath, VerifiedObjectEnvelope>,
    history: Vec<ObjectId>,
    rollback_history: Option<VerifiedRemoteHistory>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GitPublicationIntentV1 {
    schema_version: u32,
    expected: RemoteRevision,
    publication_id: PublicationId,
    snapshot_digest: SnapshotDigest,
    object_oids: BTreeSet<String>,
    tree_oid: String,
    commit_oid: String,
    pack_checksum: String,
}

#[derive(Default)]
struct GitTreeNode {
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeMap<String, Self>,
}

struct ConstructedPublication {
    intent: PublicationIntent,
    pack: Vec<u8>,
    expected_oid: ObjectId,
    commit_oid: ObjectId,
}

/// A bounded credential-free Git smart-HTTPS transport.
///
/// Test root and loopback routing injection do not exist in production builds.
///
/// ```compile_fail
/// use kitrove_core::GitSyncBackend;
///
/// let _ = GitSyncBackend::open_for_test;
/// ```
pub struct GitSyncBackend {
    remote: GitRemoteUrl,
    agent: ureq::Agent,
    credential_provider: Option<GitCredentialProvider>,
}

#[cfg(test)]
#[derive(Debug)]
struct TestResolver(std::net::SocketAddr);

#[cfg(test)]
impl ureq::unversioned::resolver::Resolver for TestResolver {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut addresses = self.empty();
        addresses.push(self.0);
        Ok(addresses)
    }
}

impl GitSyncBackend {
    /// Opens one canonical HTTPS remote without performing network I/O.
    pub fn open(remote: &str, limits: SyncLimits) -> Result<Self, BackendError> {
        Self::open_with_optional_provider(remote, limits, None)
    }

    /// Opens one canonical HTTPS remote with an operation-local credential provider.
    pub fn open_with_credentials(
        remote: &str,
        limits: SyncLimits,
        provider: GitCredentialProvider,
    ) -> Result<Self, BackendError> {
        Self::open_with_optional_provider(remote, limits, Some(provider))
    }

    fn open_with_optional_provider(
        remote: &str,
        limits: SyncLimits,
        provider: Option<GitCredentialProvider>,
    ) -> Result<Self, BackendError> {
        let remote = GitRemoteUrl::parse(remote)?;
        debug_assert!(remote.as_str().starts_with(remote.origin()));
        let config = agent_config(limits, RootCerts::WebPki);
        Ok(Self {
            remote,
            agent: config.into(),
            credential_provider: provider,
        })
    }

    #[cfg(test)]
    fn open_for_test(
        remote: &str,
        limits: SyncLimits,
        root: ureq::tls::Certificate<'static>,
        address: std::net::SocketAddr,
        provider: Option<GitCredentialProvider>,
    ) -> Result<Self, BackendError> {
        let remote = GitRemoteUrl::parse(remote)?;
        let config = agent_config(limits, RootCerts::from([root]));
        let agent = ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::default(),
            TestResolver(address),
        );
        Ok(Self {
            remote,
            agent,
            credential_provider: provider,
        })
    }

    /// Returns the stable redacted synchronization identity.
    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        self.remote.remote_key()
    }

    /// Reads and validates the selected fixed-ref snapshot under explicit bounds.
    pub fn inspect(&self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        self.inspect_observation(limits).map(|value| value.remote)
    }

    fn inspect_observation(&self, limits: SyncLimits) -> Result<GitObservation, BackendError> {
        let mut budget = GitBudget::new(limits);
        let mut authentication = GitAuthentication::new(self.credential_provider.as_ref());
        let deadline = GitOperationDeadline::new(limits)?;
        let url = self
            .remote
            .service_url("/info/refs", Some("service=git-upload-pack"))?;
        let response = self.send_authenticated(
            &mut authentication,
            limits,
            &mut budget,
            &deadline,
            |authorization| {
                let mut request = self
                    .agent
                    .get(url.as_str())
                    .config()
                    .timeout_global(Some(deadline.remaining()?))
                    .build()
                    .header("Accept", "application/x-git-upload-pack-advertisement");
                if let Some(authorization) = authorization {
                    request = request.header("Authorization", authorization);
                }
                request.call().map_err(|_| transport_failed())
            },
        )?;
        let body = read_response(
            response,
            "application/x-git-upload-pack-advertisement",
            limits.git().max_advertisement_bytes(),
            &mut budget,
        )?;
        let advertisement = parse_advertisement(&body, b"git-upload-pack", limits, &mut budget)?;
        let fetched = match advertisement.selected {
            Some(oid) => Some(self.fetch_selected(
                oid,
                &advertisement.capabilities,
                limits,
                &mut budget,
                &mut authentication,
                &deadline,
            )?),
            None => None,
        };
        finish_git_observation(advertisement.selected, fetched, limits)
    }

    /// Deterministically prepares a byte-bound publication intent without network I/O.
    pub fn prepare_publication(
        &self,
        expected: &RemoteRevision,
        publication_id: &PublicationId,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationIntent, BackendError> {
        prepare_git_publication(expected, publication_id, staged, objects, limits)
    }

    /// Attempts the exact conditional publication bound by a durable intent.
    pub fn publish(
        &self,
        intent: &PublicationIntent,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        publish_git(self, intent, staged, objects, limits)
    }

    fn send_authenticated(
        &self,
        authentication: &mut GitAuthentication<'_>,
        limits: SyncLimits,
        budget: &mut GitBudget,
        deadline: &GitOperationDeadline,
        send: impl Fn(Option<&str>) -> Result<ureq::http::Response<ureq::Body>, BackendError>,
    ) -> Result<ureq::http::Response<ureq::Body>, BackendError> {
        let response = send(authentication.header.as_deref().map(String::as_str))?;
        deadline.remaining()?;
        if response.status() != 401 {
            return Ok(response);
        }
        parse_basic_challenge(response.headers())?;
        consume_refused_response(response, limits, budget)?;
        deadline.remaining()?;
        if authentication.challenged || authentication.header.is_some() {
            return Err(authentication_failed());
        }
        authentication.challenged = true;
        let credential = authentication
            .provider
            .as_ref()
            .and_then(|provider| (provider.source)())
            .ok_or_else(authentication_failed)?;
        authentication.header = Some(basic_authorization(credential)?);
        let response = send(authentication.header.as_deref().map(String::as_str))?;
        deadline.remaining()?;
        if response.status() == 401 {
            consume_refused_response(response, limits, budget)?;
            return Err(authentication_failed());
        }
        Ok(response)
    }

    fn fetch_selected(
        &self,
        selected: ObjectId,
        capabilities: &BTreeSet<Vec<u8>>,
        limits: SyncLimits,
        budget: &mut GitBudget,
        authentication: &mut GitAuthentication<'_>,
        deadline: &GitOperationDeadline,
    ) -> Result<FetchedGit, BackendError> {
        require_upload_capabilities(capabilities)?;
        let request = build_upload_request(selected, capabilities, limits)?;
        if request.len() as u64 > limits.git().max_request_body_bytes() {
            return Err(limit_exceeded());
        }
        let url = self.remote.service_url("/git-upload-pack", None)?;
        let response =
            self.send_authenticated(authentication, limits, budget, deadline, |authorization| {
                let mut request_builder = self
                    .agent
                    .post(url.as_str())
                    .config()
                    .timeout_global(Some(deadline.remaining()?))
                    .build()
                    .header("Accept", "application/x-git-upload-pack-result")
                    .header("Content-Type", "application/x-git-upload-pack-request");
                if let Some(authorization) = authorization {
                    request_builder = request_builder.header("Authorization", authorization);
                }
                request_builder
                    .send(request.as_slice())
                    .map_err(|_| transport_failed())
            })?;
        let response_limit = limits
            .git()
            .max_received_pack_bytes()
            .checked_add(limits.git().max_advertisement_bytes())
            .ok_or_else(limit_exceeded)?;
        let body = read_response(
            response,
            "application/x-git-upload-pack-result",
            response_limit,
            budget,
        )?;
        let response = extract_pack_response(&body, limits, budget)?;
        let objects = decode_pack(response.pack, limits, budget)?;
        Ok(FetchedGit {
            objects,
            shallow: response.shallow,
        })
    }
}

fn finish_git_observation(
    selected: Option<ObjectId>,
    fetched: Option<FetchedGit>,
    limits: SyncLimits,
) -> Result<GitObservation, BackendError> {
    match (selected, fetched) {
        (Some(oid), Some(fetched)) => {
            let verified = verify_selected_history(oid, &fetched, limits)?;
            debug_assert_eq!(verified.commits.first(), Some(&oid));
            let rollback_history = VerifiedRemoteHistory::new(verified.snapshots, limits)
                .map_err(|_| invalid_history())?;
            let current = rollback_history
                .snapshots()
                .first()
                .ok_or_else(invalid_history)?;
            Ok(GitObservation {
                remote: RemoteSnapshot::present(
                    current.revision().clone(),
                    current.snapshot().clone(),
                ),
                objects: verified.objects,
                history: verified.commits,
                rollback_history: Some(rollback_history),
            })
        }
        (None, None) => {
            let revision =
                RemoteRevision::parse("git:absent:v1").map_err(|_| invalid_protocol())?;
            Ok(GitObservation {
                remote: RemoteSnapshot::absent(revision),
                objects: BTreeMap::new(),
                history: Vec::new(),
                rollback_history: None,
            })
        }
        _ => Err(invalid_protocol()),
    }
}

fn agent_config(limits: SyncLimits, roots: RootCerts) -> ureq::config::Config {
    let git = limits.git();
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .tls_config(tls)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(true)
        .user_agent(USER_AGENT)
        .accept_encoding("")
        .max_response_header_size(git.max_response_header_bytes())
        .input_buffer_size(git.http_input_buffer_bytes())
        .output_buffer_size(git.http_output_buffer_bytes())
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .timeout_connect(Some(Duration::from_millis(git.connect_timeout_ms())))
        .timeout_recv_response(Some(Duration::from_millis(
            git.response_header_timeout_ms(),
        )))
        .timeout_recv_body(Some(Duration::from_millis(git.body_read_timeout_ms())))
        .timeout_per_call(Some(Duration::from_millis(git.exchange_deadline_ms())))
        .timeout_global(Some(Duration::from_millis(git.operation_deadline_ms())))
        .build()
}

impl Debug for GitSyncBackend {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitSyncBackend")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl Sealed for GitSyncBackend {}

impl SyncBackend for GitSyncBackend {
    type ReadSession<'a> = GitReadSession;

    type ApplySession<'a> = GitApplySession<'a>;

    fn inspect(&self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        GitSyncBackend::inspect(self, limits)
    }

    fn fetch_object(
        &self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        let observed = self.inspect_observation(limits)?;
        fetch_observed_object(&observed, descriptor)
    }

    fn begin_read(&self, limits: SyncLimits) -> Result<Self::ReadSession<'_>, BackendError> {
        Ok(GitReadSession {
            observed: self.inspect_observation(limits)?,
        })
    }

    fn begin_apply(&self, limits: SyncLimits) -> Result<Self::ApplySession<'_>, BackendError> {
        Ok(GitApplySession {
            backend: self,
            observed: self.inspect_observation(limits)?,
        })
    }
}

/// One immutable, fully verified Git read observation.
pub struct GitReadSession {
    observed: GitObservation,
}

impl SyncBackendRead for GitReadSession {
    fn inspect(&mut self, _limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        Ok(self.observed.remote.clone())
    }

    fn inspect_history(
        &mut self,
        _limits: SyncLimits,
    ) -> Result<VerifiedRemoteHistory, BackendError> {
        self.observed
            .rollback_history
            .clone()
            .ok_or_else(invalid_history)
    }

    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        _limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_observed_object(&self.observed, descriptor)
    }
}

/// One Git apply session whose exact-old receive command is the remote CAS boundary.
pub struct GitApplySession<'a> {
    backend: &'a GitSyncBackend,
    observed: GitObservation,
}

impl SyncBackendApply for GitApplySession<'_> {
    fn inspect(&mut self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        self.observed = self.backend.inspect_observation(limits)?;
        Ok(self.observed.remote.clone())
    }

    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        _limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_observed_object(&self.observed, descriptor)
    }

    fn prepare_publication(
        &mut self,
        expected: &RemoteRevision,
        publication_id: &PublicationId,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationIntent, BackendError> {
        if self.observed.remote.revision() != expected {
            return Err(stale());
        }
        prepare_git_publication(expected, publication_id, staged, objects, limits)
    }

    fn publish(
        &mut self,
        intent: &PublicationIntent,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        publish_git(self.backend, intent, staged, objects, limits)
    }

    fn reconcile(
        &mut self,
        intent: &PublicationIntent,
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        let parsed = parse_publication_intent(intent, limits)?;
        let proposed =
            ObjectId::from_hex(parsed.commit_oid.as_bytes()).map_err(|_| intent_invalid())?;
        let Ok(observed) = self.backend.inspect_observation(limits) else {
            return Ok(PublicationStatus::Uncertain);
        };
        self.observed = observed;
        Ok(reconcile_git_observation(
            intent,
            &parsed,
            proposed,
            &self.observed,
        ))
    }
}

fn reconcile_git_observation(
    intent: &PublicationIntent,
    parsed: &GitPublicationIntentV1,
    proposed: ObjectId,
    observed: &GitObservation,
) -> PublicationStatus {
    if observed.history.contains(&proposed) {
        return PublicationStatus::Published(intent.proposed_revision().clone());
    }
    if observed.remote.revision() == &parsed.expected {
        return PublicationStatus::Ready;
    }
    PublicationStatus::Uncertain
}

fn fetch_observed_object(
    observed: &GitObservation,
    descriptor: &ObjectDescriptor,
) -> Result<VerifiedObjectEnvelope, BackendError> {
    let object = observed
        .objects
        .get(descriptor.root())
        .ok_or_else(object_mismatch)?;
    if object.descriptor() != descriptor {
        return Err(object_mismatch());
    }
    Ok(object.clone())
}

fn prepare_git_publication(
    expected: &RemoteRevision,
    publication_id: &PublicationId,
    staged: &PortableSnapshotV1,
    supplied: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<PublicationIntent, BackendError> {
    construct_git_publication(expected, publication_id, staged, supplied, limits)
        .map(|constructed| constructed.intent)
}

fn validate_git_publication(
    intent: &PublicationIntent,
    staged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<ConstructedPublication, BackendError> {
    let parsed = parse_publication_intent(intent, limits)?;
    let constructed = construct_git_publication(
        &parsed.expected,
        &parsed.publication_id,
        staged,
        objects,
        limits,
    )?;
    if constructed.intent != *intent {
        return Err(intent_invalid());
    }
    Ok(constructed)
}

fn construct_git_publication(
    expected: &RemoteRevision,
    publication_id: &PublicationId,
    staged: &PortableSnapshotV1,
    supplied: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<ConstructedPublication, BackendError> {
    let supplied_descriptors: BTreeSet<_> = supplied
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    if supplied_descriptors != *staged.objects() {
        return Err(object_mismatch());
    }
    let mut total = 0_u64;
    let mut flat = BTreeMap::new();
    insert_flat(
        &mut flat,
        PortablePath::parse("snapshot.json").map_err(|_| invalid_tree())?,
        staged
            .to_json(limits)
            .map_err(|_| invalid_tree())?
            .into_bytes(),
    )?;
    for envelope in supplied {
        let descriptor = envelope.descriptor();
        total = total
            .checked_add(descriptor.encoded_len())
            .ok_or_else(limit_exceeded)?;
        if descriptor.encoded_len() > limits.max_object_bytes()
            || total > limits.max_total_object_bytes()
        {
            return Err(limit_exceeded());
        }
        let prefix = format!("objects/{}/", descriptor.root().as_str());
        let empty_tree = CapturedTree {
            hash: hash_tree(&BTreeMap::new()),
            files: BTreeMap::new(),
        };
        let (metadata, tree) = match envelope {
            VerifiedObjectEnvelope::Portable { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::Native { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::NativeExtension { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::Document { object, .. } => (object.to_json()?, &empty_tree),
        };
        insert_flat(
            &mut flat,
            PortablePath::parse(format!("{prefix}metadata.json")).map_err(|_| invalid_tree())?,
            metadata.into_bytes(),
        )?;
        for (path, file) in &tree.files {
            insert_flat(
                &mut flat,
                PortablePath::parse(format!("{prefix}payload/{}", path.as_str()))
                    .map_err(|_| invalid_tree())?,
                file.bytes.clone(),
            )?;
        }
    }

    let mut root = GitTreeNode::default();
    for (path, bytes) in flat {
        root.insert(path.as_str(), bytes)?;
    }
    let mut objects = GitObjectMap::new();
    let tree_oid = root.store(&mut objects)?;
    let parent = parse_expected_parent(expected)?;
    let commit_data =
        deterministic_commit(tree_oid, parent, publication_id, staged.snapshot_digest());
    let commit_oid = insert_git_object(&mut objects, ObjectKind::Commit, commit_data)?;
    let pack = encode_pack(&objects, limits)?;
    let pack_checksum =
        ObjectId::from_bytes_or_panic(&pack[pack.len() - HashKind::Sha1.len_in_bytes()..]);
    let object_oids = objects.keys().map(ToString::to_string).collect();
    let persisted = GitPublicationIntentV1 {
        schema_version: 1,
        expected: expected.clone(),
        publication_id: publication_id.clone(),
        snapshot_digest: staged.snapshot_digest().clone(),
        object_oids,
        tree_oid: tree_oid.to_string(),
        commit_oid: commit_oid.to_string(),
        pack_checksum: pack_checksum.to_string(),
    };
    let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| intent_invalid())?;
    encoded.push('\n');
    let proposed =
        RemoteRevision::parse(format!("git:sha1:{commit_oid}")).map_err(|_| intent_invalid())?;
    let intent = PublicationIntent::from_persisted(encoded, proposed, limits)?;
    Ok(ConstructedPublication {
        intent,
        pack,
        expected_oid: parent.unwrap_or_else(|| ObjectId::null(HashKind::Sha1)),
        commit_oid,
    })
}

fn publish_git(
    backend: &GitSyncBackend,
    intent: &PublicationIntent,
    staged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<PublicationStatus, BackendError> {
    let constructed = validate_git_publication(intent, staged, objects, limits)?;

    let mut budget = GitBudget::new(limits);
    let mut authentication = GitAuthentication::new(backend.credential_provider.as_ref());
    let deadline = GitOperationDeadline::new(limits)?;
    let url = backend
        .remote
        .service_url("/info/refs", Some("service=git-receive-pack"))?;
    let response = backend.send_authenticated(
        &mut authentication,
        limits,
        &mut budget,
        &deadline,
        |authorization| {
            let mut request = backend
                .agent
                .get(url.as_str())
                .config()
                .timeout_global(Some(deadline.remaining()?))
                .build()
                .header("Accept", "application/x-git-receive-pack-advertisement");
            if let Some(authorization) = authorization {
                request = request.header("Authorization", authorization);
            }
            request.call().map_err(|_| transport_failed())
        },
    )?;
    let body = read_response(
        response,
        "application/x-git-receive-pack-advertisement",
        limits.git().max_advertisement_bytes(),
        &mut budget,
    )?;
    let advertisement = parse_advertisement(&body, b"git-receive-pack", limits, &mut budget)?;
    if !advertisement
        .capabilities
        .contains(b"report-status".as_slice())
    {
        return Err(invalid_protocol());
    }
    let advertised_oid = advertisement
        .selected
        .unwrap_or_else(|| ObjectId::null(HashKind::Sha1));
    if advertised_oid != constructed.expected_oid {
        return Ok(PublicationStatus::Uncertain);
    }

    let request = build_receive_request(
        constructed.expected_oid,
        constructed.commit_oid,
        &constructed.pack,
        limits,
    )?;
    let url = backend.remote.service_url("/git-receive-pack", None)?;
    let response = match backend.send_authenticated(
        &mut authentication,
        limits,
        &mut budget,
        &deadline,
        |authorization| {
            let mut request_builder = backend
                .agent
                .post(url.as_str())
                .config()
                .timeout_global(Some(deadline.remaining()?))
                .build()
                .header("Accept", "application/x-git-receive-pack-result")
                .header("Content-Type", "application/x-git-receive-pack-request");
            if let Some(authorization) = authorization {
                request_builder = request_builder.header("Authorization", authorization);
            }
            request_builder
                .send(request.as_slice())
                .map_err(|_| transport_failed())
        },
    ) {
        Ok(response) => response,
        Err(_) => return Ok(PublicationStatus::Uncertain),
    };
    let body = match read_response(
        response,
        "application/x-git-receive-pack-result",
        limits.git().max_advertisement_bytes(),
        &mut budget,
    ) {
        Ok(body) => body,
        Err(_) => return Ok(PublicationStatus::Uncertain),
    };
    if parse_receive_status(&body, &mut budget).is_err() {
        return Ok(PublicationStatus::Uncertain);
    }
    Ok(PublicationStatus::Published(
        intent.proposed_revision().clone(),
    ))
}

fn parse_publication_intent(
    intent: &PublicationIntent,
    limits: SyncLimits,
) -> Result<GitPublicationIntentV1, BackendError> {
    if intent.as_persisted().len() as u64 > limits.max_control_bytes() {
        return Err(intent_invalid());
    }
    let parsed: GitPublicationIntentV1 =
        serde_json::from_str(intent.as_persisted()).map_err(|_| intent_invalid())?;
    if parsed.schema_version != 1
        || ObjectId::from_hex(parsed.tree_oid.as_bytes()).is_err()
        || ObjectId::from_hex(parsed.commit_oid.as_bytes()).is_err()
        || ObjectId::from_hex(parsed.pack_checksum.as_bytes()).is_err()
        || parsed.object_oids.is_empty()
        || !parsed.object_oids.contains(&parsed.tree_oid)
        || !parsed.object_oids.contains(&parsed.commit_oid)
        || parsed
            .object_oids
            .iter()
            .any(|oid| ObjectId::from_hex(oid.as_bytes()).is_err())
        || intent.proposed_revision().as_str() != format!("git:sha1:{}", parsed.commit_oid)
    {
        return Err(intent_invalid());
    }
    let mut canonical = serde_json::to_string_pretty(&parsed).map_err(|_| intent_invalid())?;
    canonical.push('\n');
    if canonical != intent.as_persisted() {
        return Err(intent_invalid());
    }
    Ok(parsed)
}

fn build_receive_request(
    old: ObjectId,
    new: ObjectId,
    pack: &[u8],
    limits: SyncLimits,
) -> Result<Vec<u8>, BackendError> {
    let command = format!(
        "{old} {new} {}\0report-status\n",
        std::str::from_utf8(FIXED_REF).map_err(|_| invalid_protocol())?
    );
    let mut request = Vec::new();
    encode_packet_line(command.as_bytes(), &mut request)?;
    request.extend_from_slice(b"0000");
    request.extend_from_slice(pack);
    if request.len() as u64 > limits.git().max_request_body_bytes() {
        return Err(limit_exceeded());
    }
    Ok(request)
}

fn parse_receive_status(input: &[u8], budget: &mut GitBudget) -> Result<(), BackendError> {
    let mut packets = PacketCursor::new(input, &mut budget.remaining_packet_lines);
    if packets.next()? != Some(PacketLine::Data(b"unpack ok\n")) {
        return Err(invalid_protocol());
    }
    let expected = [b"ok ".as_slice(), FIXED_REF, b"\n"].concat();
    if packets.next()? != Some(PacketLine::Data(&expected))
        || packets.next()? != Some(PacketLine::Flush)
        || packets.next()?.is_some()
    {
        return Err(invalid_protocol());
    }
    Ok(())
}

fn encode_pack(objects: &GitObjectMap, limits: SyncLimits) -> Result<Vec<u8>, BackendError> {
    let count = u32::try_from(objects.len()).map_err(|_| limit_exceeded())?;
    let mut pack = gix_pack::data::header::encode(gix_pack::data::Version::V2, count).to_vec();
    for object in objects.values() {
        let header = match object.kind {
            ObjectKind::Commit => gix_pack::data::entry::Header::Commit,
            ObjectKind::Tree => gix_pack::data::entry::Header::Tree,
            ObjectKind::Blob => gix_pack::data::entry::Header::Blob,
            ObjectKind::Tag => return Err(invalid_pack()),
        };
        header
            .write_to(object.data.len() as u64, &mut pack)
            .map_err(|_| invalid_pack())?;
        let mut compressed =
            gix_zlib::stream::deflate::Write::new(pack, gix_zlib::Compression::DEFAULT);
        write_bytes(&mut compressed, &object.data)?;
        compressed.flush().map_err(|_| invalid_pack())?;
        pack = compressed.into_inner();
        if pack.len() as u64 > limits.git().max_received_pack_bytes() {
            return Err(limit_exceeded());
        }
    }
    let mut hasher = gix_hash::hasher(HashKind::Sha1);
    hasher.update(&pack);
    let checksum = hasher.try_finalize().map_err(|_| invalid_pack())?;
    pack.extend_from_slice(checksum.as_slice());
    if pack.len() as u64 > limits.git().max_received_pack_bytes()
        || pack.len() as u64 > limits.git().max_request_body_bytes()
    {
        return Err(limit_exceeded());
    }
    Ok(pack)
}

fn write_bytes(writer: &mut impl std::io::Write, mut bytes: &[u8]) -> Result<(), BackendError> {
    while !bytes.is_empty() {
        let written = writer.write(bytes).map_err(|_| invalid_pack())?;
        if written == 0 {
            return Err(invalid_pack());
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

impl GitTreeNode {
    fn insert(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), BackendError> {
        let (name, remainder) = path.split_once('/').unwrap_or((path, ""));
        if name.is_empty() || self.files.contains_key(name) {
            return Err(invalid_tree());
        }
        if remainder.is_empty() {
            if self.directories.contains_key(name)
                || self.files.insert(name.to_owned(), bytes).is_some()
            {
                return Err(invalid_tree());
            }
            return Ok(());
        }
        self.directories
            .entry(name.to_owned())
            .or_default()
            .insert(remainder, bytes)
    }

    fn store(&self, objects: &mut GitObjectMap) -> Result<ObjectId, BackendError> {
        let mut entries = Vec::new();
        for (name, bytes) in &self.files {
            let oid = insert_git_object(objects, ObjectKind::Blob, bytes.clone())?;
            entries.push((name, false, oid));
        }
        for (name, tree) in &self.directories {
            entries.push((name, true, tree.store(objects)?));
        }
        entries.sort_by(|left, right| {
            git_tree_key(left.0, left.1).cmp(&git_tree_key(right.0, right.1))
        });
        let mut data = Vec::new();
        for (name, directory, oid) in entries {
            data.extend_from_slice(if directory { b"40000 " } else { b"100644 " });
            data.extend_from_slice(name.as_bytes());
            data.push(0);
            data.extend_from_slice(oid.as_slice());
        }
        insert_git_object(objects, ObjectKind::Tree, data)
    }
}

fn insert_flat(
    files: &mut BTreeMap<PortablePath, Vec<u8>>,
    path: PortablePath,
    bytes: Vec<u8>,
) -> Result<(), BackendError> {
    if files.insert(path, bytes).is_some() {
        return Err(invalid_tree());
    }
    Ok(())
}

fn insert_git_object(
    objects: &mut GitObjectMap,
    kind: ObjectKind,
    data: Vec<u8>,
) -> Result<ObjectId, BackendError> {
    let oid = gix_object::compute_hash(HashKind::Sha1, kind, &data).map_err(|_| invalid_pack())?;
    match objects.get(&oid) {
        Some(existing) if existing.kind == kind && existing.data == data => {}
        Some(_) => return Err(invalid_pack()),
        None => {
            objects.insert(oid, GitObject { kind, data });
        }
    }
    Ok(oid)
}

fn git_tree_key(name: &str, directory: bool) -> Vec<u8> {
    let mut key = name.as_bytes().to_vec();
    if directory {
        key.push(b'/');
    }
    key
}

fn parse_expected_parent(expected: &RemoteRevision) -> Result<Option<ObjectId>, BackendError> {
    if expected.as_str() == "git:absent:v1" {
        return Ok(None);
    }
    expected
        .as_str()
        .strip_prefix("git:sha1:")
        .and_then(|value| ObjectId::from_hex(value.as_bytes()).ok())
        .map(Some)
        .ok_or_else(intent_invalid)
}

fn deterministic_commit(
    tree: ObjectId,
    parent: Option<ObjectId>,
    publication_id: &PublicationId,
    snapshot_digest: &SnapshotDigest,
) -> Vec<u8> {
    let mut commit = format!("tree {tree}\n");
    if let Some(parent) = parent {
        commit.push_str(&format!("parent {parent}\n"));
    }
    commit.push_str(
        "author KitRove <sync@kitrove.invalid> 0 +0000\ncommitter KitRove <sync@kitrove.invalid> 0 +0000\n\nkitrove-sync-v1\npublication ",
    );
    commit.push_str(publication_id.as_str());
    commit.push_str("\nsnapshot ");
    commit.push_str(snapshot_digest.as_str());
    commit.push('\n');
    commit.into_bytes()
}

fn build_upload_request(
    selected: ObjectId,
    capabilities: &BTreeSet<Vec<u8>>,
    limits: SyncLimits,
) -> Result<Vec<u8>, BackendError> {
    let mut requested = vec![b"shallow".as_slice(), b"no-progress".as_slice()];
    if capabilities.contains(b"ofs-delta".as_slice()) {
        requested.push(b"ofs-delta");
    }
    let mut want = format!("want {selected}").into_bytes();
    for capability in requested {
        want.push(b' ');
        want.extend_from_slice(capability);
    }
    want.push(b'\n');

    let depth = limits
        .max_backend_history()
        .checked_add(1)
        .ok_or_else(limit_exceeded)?;
    let mut output = Vec::new();
    encode_packet_line(&want, &mut output)?;
    encode_packet_line(format!("deepen {depth}\n").as_bytes(), &mut output)?;
    output.extend_from_slice(b"0000");
    encode_packet_line(b"done\n", &mut output)?;
    Ok(output)
}

fn require_upload_capabilities(capabilities: &BTreeSet<Vec<u8>>) -> Result<(), BackendError> {
    if capabilities.contains(b"shallow".as_slice())
        && capabilities.contains(b"no-progress".as_slice())
    {
        Ok(())
    } else {
        Err(invalid_protocol())
    }
}

struct PackResponse<'a> {
    pack: &'a [u8],
    shallow: BTreeSet<ObjectId>,
}

fn extract_pack_response<'a>(
    input: &'a [u8],
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<PackResponse<'a>, BackendError> {
    let mut shallow_records = 0_usize;
    let mut shallow = BTreeSet::new();
    let offset = {
        let mut packets = PacketCursor::new(input, &mut budget.remaining_packet_lines);
        loop {
            match packets.next()? {
                Some(PacketLine::Data(line))
                    if line.starts_with(b"shallow ") || line.starts_with(b"unshallow ") =>
                {
                    shallow_records = shallow_records.checked_add(1).ok_or_else(limit_exceeded)?;
                    if shallow_records > limits.max_backend_history().saturating_add(1)
                        || line.len() != 49
                        || !line.ends_with(b"\n")
                    {
                        return Err(invalid_protocol());
                    }
                    let oid = ObjectId::from_hex(&line[line.len() - 41..line.len() - 1])
                        .map_err(|_| invalid_protocol())?;
                    if line.starts_with(b"unshallow ") || !shallow.insert(oid) {
                        return Err(invalid_protocol());
                    }
                }
                Some(PacketLine::Flush) => break,
                _ => return Err(invalid_protocol()),
            }
        }
        if packets.next()? != Some(PacketLine::Data(b"NAK\n")) {
            return Err(invalid_protocol());
        }
        packets.offset
    };
    let pack = input.get(offset..).ok_or_else(invalid_protocol)?;
    if !pack.starts_with(b"PACK") {
        return Err(invalid_protocol());
    }
    if pack.len() as u64 > limits.git().max_received_pack_bytes() {
        return Err(limit_exceeded());
    }
    Ok(PackResponse { pack, shallow })
}

fn decode_pack(
    input: &[u8],
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<GitObjectMap, BackendError> {
    let hash_bytes = HashKind::Sha1.len_in_bytes();
    if input.len() < 12 + hash_bytes || input.len() as u64 > limits.git().max_received_pack_bytes()
    {
        return Err(invalid_pack());
    }
    let pack_end = input.len() - hash_bytes;
    let mut hasher = gix_hash::hasher(HashKind::Sha1);
    hasher.update(&input[..pack_end]);
    let checksum = hasher.try_finalize().map_err(|_| invalid_pack())?;
    if checksum.as_slice() != &input[pack_end..] {
        return Err(invalid_pack());
    }

    let pack = gix_pack::data::File::from_data(input.to_vec(), PathBuf::new(), HashKind::Sha1)
        .map_err(|_| invalid_pack())?
        .with_alloc_limit_bytes(Some(
            usize::try_from(limits.git().max_decoded_object_bytes())
                .map_err(|_| limit_exceeded())?,
        ));
    let object_count = usize::try_from(pack.num_objects()).map_err(|_| limit_exceeded())?;
    if object_count > budget.remaining_decoded_objects {
        return Err(limit_exceeded());
    }

    let mut objects = GitObjectMap::new();
    let mut offset = 12_u64;
    let mut inflate = gix_zlib::Inflate::default();
    let mut cache = gix_pack::cache::Never;
    for _ in 0..object_count {
        let entry = pack.entry(offset).map_err(|_| invalid_pack())?;
        if entry.decompressed_size > limits.git().max_decoded_object_bytes() {
            return Err(limit_exceeded());
        }
        let resolve_header = |id: &gix_hash::oid| {
            objects.get(id).map(
                |object| gix_pack::data::decode::header::ResolvedBase::OutOfPack {
                    kind: object.kind,
                    num_deltas: Some(0),
                },
            )
        };
        let header = pack
            .decode_header(entry.clone(), &mut inflate, &resolve_header)
            .map_err(|_| invalid_pack())?;
        if header.num_deltas as usize > limits.git().max_delta_depth()
            || header.object_size > limits.git().max_decoded_object_bytes()
            || header.object_size > budget.remaining_decoded_bytes
        {
            return Err(limit_exceeded());
        }
        if header.kind == ObjectKind::Tag {
            return Err(invalid_pack());
        }
        let probe_len = usize::try_from(entry.decompressed_size).map_err(|_| limit_exceeded())?;
        let mut probe = Vec::new();
        probe
            .try_reserve_exact(probe_len)
            .map_err(|_| limit_exceeded())?;
        probe.resize(probe_len, 0);
        let compressed_size = pack
            .decompress_entry(&entry, &mut inflate, &mut probe)
            .map_err(|_| invalid_pack())?;
        let next_offset = entry
            .data_offset
            .checked_add(u64::try_from(compressed_size).map_err(|_| invalid_pack())?)
            .ok_or_else(invalid_pack)?;
        if next_offset > pack.pack_end() as u64 {
            return Err(invalid_pack());
        }

        let resolve = |id: &gix_hash::oid, out: &mut Vec<u8>| {
            let id = id.to_owned();
            let object: &GitObject = objects.get(&id)?;
            out.clear();
            out.try_reserve_exact(object.data.len()).ok()?;
            out.extend_from_slice(&object.data);
            Some(gix_pack::data::decode::entry::ResolvedBase::OutOfPack {
                kind: object.kind,
                end: object.data.len(),
            })
        };
        let mut decoded = Vec::new();
        let outcome = pack
            .decode_entry(
                entry.clone(),
                &mut decoded,
                &mut inflate,
                &resolve,
                &mut cache,
            )
            .map_err(|_| invalid_pack())?;
        if outcome.num_deltas as usize > limits.git().max_delta_depth()
            || outcome.object_size > limits.git().max_decoded_object_bytes()
            || decoded.len() as u64 != outcome.object_size
            || outcome.kind != header.kind
            || outcome.object_size != header.object_size
        {
            return Err(limit_exceeded());
        }
        if outcome.kind == ObjectKind::Tag {
            return Err(invalid_pack());
        }
        budget.charge_object(outcome.object_size)?;
        let oid = gix_object::compute_hash(HashKind::Sha1, outcome.kind, &decoded)
            .map_err(|_| invalid_pack())?;
        if objects
            .insert(
                oid,
                GitObject {
                    kind: outcome.kind,
                    data: decoded,
                },
            )
            .is_some()
        {
            return Err(invalid_pack());
        }
        offset = next_offset;
    }
    if offset != pack.pack_end() as u64 {
        return Err(invalid_pack());
    }
    Ok(objects)
}

#[cfg(test)]
fn verify_selected_snapshot(
    selected: ObjectId,
    fetched: &FetchedGit,
    limits: SyncLimits,
) -> Result<VerifiedGitSnapshot, BackendError> {
    let history = verify_commit_chain(selected, fetched, limits)?;
    let (_, tree) = history.first().ok_or_else(invalid_history)?;
    let mut snapshot_budget = limits.max_snapshot_bytes();
    let mut traversal_budget = limits.git().max_decoded_objects();
    let (snapshot, objects) = verify_snapshot_tree(
        *tree,
        fetched,
        limits,
        &mut snapshot_budget,
        &mut traversal_budget,
    )?;
    Ok(VerifiedGitSnapshot {
        snapshot,
        objects,
        history: history.into_iter().map(|(commit, _)| commit).collect(),
    })
}

fn verify_selected_history(
    selected: ObjectId,
    fetched: &FetchedGit,
    limits: SyncLimits,
) -> Result<VerifiedGitHistory, BackendError> {
    let history = verify_commit_chain(selected, fetched, limits)?;
    let mut snapshots = Vec::with_capacity(history.len());
    let mut objects: BTreeMap<PortablePath, VerifiedObjectEnvelope> = BTreeMap::new();
    let mut verified_trees: BTreeMap<ObjectId, Arc<PortableSnapshotV1>> = BTreeMap::new();
    let mut snapshot_budget = limits.max_snapshot_bytes();
    let mut traversal_budget = limits.git().max_decoded_objects();
    for (commit, tree) in &history {
        let snapshot = if let Some(snapshot) = verified_trees.get(tree) {
            Arc::clone(snapshot)
        } else {
            let (snapshot, snapshot_objects) = verify_snapshot_tree(
                *tree,
                fetched,
                limits,
                &mut snapshot_budget,
                &mut traversal_budget,
            )?;
            for (root, object) in snapshot_objects {
                match objects.get(&root) {
                    Some(existing) if existing.descriptor() == object.descriptor() => {}
                    Some(_) => return Err(invalid_tree()),
                    None => {
                        objects.insert(root, object);
                    }
                }
            }
            let snapshot = Arc::new(snapshot);
            verified_trees.insert(*tree, Arc::clone(&snapshot));
            snapshot
        };
        let revision =
            RemoteRevision::parse(format!("git:sha1:{commit}")).map_err(|_| invalid_history())?;
        snapshots.push((revision, snapshot));
    }
    validate_descriptor_budget(
        objects.values().map(VerifiedObjectEnvelope::descriptor),
        limits,
    )
    .map_err(|_| limit_exceeded())?;
    Ok(VerifiedGitHistory {
        snapshots,
        objects,
        commits: history.into_iter().map(|(commit, _)| commit).collect(),
    })
}

fn verify_snapshot_tree(
    tree: ObjectId,
    fetched: &FetchedGit,
    limits: SyncLimits,
    snapshot_budget: &mut u64,
    traversal_budget: &mut usize,
) -> Result<
    (
        PortableSnapshotV1,
        BTreeMap<PortablePath, VerifiedObjectEnvelope>,
    ),
    BackendError,
> {
    let mut files = BTreeMap::new();
    let mut active_trees = BTreeSet::new();
    flatten_tree(
        tree,
        "",
        &fetched.objects,
        &mut active_trees,
        &mut files,
        traversal_budget,
        0,
    )?;
    let snapshot_path = PortablePath::parse("snapshot.json").map_err(|_| invalid_tree())?;
    let snapshot_blob = files.remove(&snapshot_path).ok_or_else(invalid_tree)?;
    let snapshot_bytes = u64::try_from(snapshot_blob.len()).map_err(|_| limit_exceeded())?;
    *snapshot_budget = snapshot_budget
        .checked_sub(snapshot_bytes)
        .ok_or_else(limit_exceeded)?;
    let snapshot_json = std::str::from_utf8(&snapshot_blob).map_err(|_| invalid_tree())?;
    let snapshot =
        PortableSnapshotV1::from_json(snapshot_json, limits).map_err(|_| invalid_tree())?;

    let mut verified = BTreeMap::new();
    for descriptor in snapshot.objects() {
        let object = take_verified_object(&mut files, descriptor)?;
        if object.descriptor() != descriptor
            || verified.insert(descriptor.root().clone(), object).is_some()
        {
            return Err(invalid_tree());
        }
    }
    if !files.is_empty() {
        return Err(invalid_tree());
    }
    Ok((snapshot, verified))
}

fn verify_commit_chain(
    selected: ObjectId,
    fetched: &FetchedGit,
    limits: SyncLimits,
) -> Result<Vec<(ObjectId, ObjectId)>, BackendError> {
    let mut current = selected;
    let mut history = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        if history.len() >= limits.max_backend_history() || !seen.insert(current) {
            return Err(invalid_history());
        }
        let object = fetched.objects.get(&current).ok_or_else(invalid_history)?;
        if object.kind != ObjectKind::Commit {
            return Err(invalid_history());
        }
        let commit =
            CommitRef::from_bytes(&object.data, HashKind::Sha1).map_err(|_| invalid_history())?;
        if commit.parents.len() > 1 {
            return Err(invalid_history());
        }
        let tree = ObjectId::from_hex(commit.tree.as_ref()).map_err(|_| invalid_history())?;
        history.push((current, tree));
        if commit.parents.is_empty() {
            if fetched.shallow.contains(&current) {
                return Err(invalid_history());
            }
            break;
        }
        if fetched.shallow.contains(&current) {
            return Err(limit_exceeded());
        }
        current = ObjectId::from_hex(commit.parents[0].as_ref()).map_err(|_| invalid_history())?;
    }
    Ok(history)
}

fn flatten_tree(
    oid: ObjectId,
    prefix: &str,
    objects: &GitObjectMap,
    active: &mut BTreeSet<ObjectId>,
    files: &mut BTreeMap<PortablePath, Vec<u8>>,
    remaining_visits: &mut usize,
    depth: usize,
) -> Result<(), BackendError> {
    *remaining_visits = remaining_visits.checked_sub(1).ok_or_else(limit_exceeded)?;
    if depth > 64 || !active.insert(oid) {
        return Err(invalid_tree());
    }
    let object = objects.get(&oid).ok_or_else(invalid_tree)?;
    if object.kind != ObjectKind::Tree {
        return Err(invalid_tree());
    }
    let entries = TreeRefIter::from_bytes(&object.data, HashKind::Sha1)
        .entries()
        .map_err(|_| invalid_tree())?;
    if entries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_tree());
    }
    for entry in entries {
        let name = std::str::from_utf8(entry.filename.as_ref()).map_err(|_| invalid_tree())?;
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(invalid_tree());
        }
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let child = entry.oid.to_owned();
        match entry.mode.value() {
            0o040000 => flatten_tree(
                child,
                &path,
                objects,
                active,
                files,
                remaining_visits,
                depth + 1,
            )?,
            0o100644 => {
                *remaining_visits = remaining_visits.checked_sub(1).ok_or_else(limit_exceeded)?;
                let path = PortablePath::parse(path).map_err(|_| invalid_tree())?;
                let blob = objects.get(&child).ok_or_else(invalid_tree)?;
                if blob.kind != ObjectKind::Blob || files.insert(path, blob.data.clone()).is_some()
                {
                    return Err(invalid_tree());
                }
            }
            _ => return Err(invalid_tree()),
        }
    }
    active.remove(&oid);
    Ok(())
}

fn take_verified_object(
    files: &mut BTreeMap<PortablePath, Vec<u8>>,
    descriptor: &ObjectDescriptor,
) -> Result<VerifiedObjectEnvelope, BackendError> {
    let prefix = format!("objects/{}/", descriptor.root().as_str());
    let metadata_path =
        PortablePath::parse(format!("{prefix}metadata.json")).map_err(|_| invalid_tree())?;
    let metadata = files.remove(&metadata_path).ok_or_else(invalid_tree)?;
    let metadata = std::str::from_utf8(&metadata).map_err(|_| invalid_tree())?;
    let payload_prefix = format!("{prefix}payload/");
    let paths: Vec<_> = files
        .keys()
        .filter(|path| path.as_str().starts_with(&payload_prefix))
        .cloned()
        .collect();
    let mut payload = BTreeMap::new();
    for path in paths {
        let relative = path
            .as_str()
            .strip_prefix(&payload_prefix)
            .ok_or_else(invalid_tree)?;
        let relative = PortablePath::parse(relative).map_err(|_| invalid_tree())?;
        let bytes = files.remove(&path).ok_or_else(invalid_tree)?;
        if payload
            .insert(
                relative,
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes,
                },
            )
            .is_some()
        {
            return Err(invalid_tree());
        }
    }
    let tree = CapturedTree {
        hash: hash_tree(&payload),
        files: payload,
    };
    match descriptor.kind() {
        SnapshotObjectKind::PortableSkillTree => {
            let object =
                StoredSkillTree::from_stored(metadata, tree).map_err(|_| invalid_tree())?;
            VerifiedObjectEnvelope::portable(descriptor.root().clone(), object)
        }
        SnapshotObjectKind::NativeSkillObject => {
            let object =
                NativeSkillObject::from_stored(metadata, tree).map_err(|_| invalid_tree())?;
            VerifiedObjectEnvelope::native(descriptor.root().clone(), object)
        }
        SnapshotObjectKind::NativeExtensionObject => {
            let object = crate::NativeExtensionObject::from_stored(metadata, tree)
                .map_err(|_| invalid_tree())?;
            VerifiedObjectEnvelope::native_extension(descriptor.root().clone(), object)
        }
        kind @ (SnapshotObjectKind::PortableInstruction
        | SnapshotObjectKind::NativeInstruction
        | SnapshotObjectKind::PortablePromptCommand
        | SnapshotObjectKind::NativePromptCommand
        | SnapshotObjectKind::PortableAgent
        | SnapshotObjectKind::NativeAgent
        | SnapshotObjectKind::PortableMcp
        | SnapshotObjectKind::NativeMcp) => {
            if !tree.files.is_empty() {
                return Err(invalid_tree());
            }
            VerifiedObjectEnvelope::document(
                descriptor.root().clone(),
                VerifiedDocumentObject::from_json(
                    kind,
                    metadata,
                    usize::try_from(descriptor.encoded_len()).map_err(|_| limit_exceeded())?,
                )?,
            )
        }
    }
}

fn encode_packet_line(payload: &[u8], output: &mut Vec<u8>) -> Result<(), BackendError> {
    let length = payload.len().checked_add(4).ok_or_else(limit_exceeded)?;
    if length > MAX_PACKET_LINE_BYTES {
        return Err(limit_exceeded());
    }
    output.extend_from_slice(format!("{length:04x}").as_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

fn read_response(
    response: ureq::http::Response<ureq::Body>,
    expected_content_type: &str,
    byte_limit: u64,
    budget: &mut GitBudget,
) -> Result<Vec<u8>, BackendError> {
    if response.status() != 200
        || response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            != Some(expected_content_type)
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(transport_failed());
    }
    let limit = byte_limit.min(budget.remaining_response_bytes);
    if let Some(value) = response.headers().get("content-length") {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(transport_failed)?;
        if length > limit {
            return Err(limit_exceeded());
        }
    }
    let mut bytes = Vec::new();
    let mut reader = response.into_body().into_reader().take(limit + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| transport_failed())?;
    if bytes.len() as u64 > limit {
        return Err(limit_exceeded());
    }
    budget.charge_response(bytes.len() as u64)?;
    Ok(bytes)
}

fn parse_basic_challenge(headers: &ureq::http::HeaderMap) -> Result<(), BackendError> {
    let mut values = headers.get_all("www-authenticate").iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(authentication_failed)?;
    if values.next().is_some() {
        return Err(authentication_failed());
    }
    let (scheme, parameters) = value.split_once(' ').ok_or_else(authentication_failed)?;
    let realm = parameters
        .strip_prefix("realm=\"")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(authentication_failed)?;
    if !scheme.eq_ignore_ascii_case("Basic")
        || realm.is_empty()
        || realm.len() > MAX_REALM_BYTES
        || realm
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'\\'))
    {
        return Err(authentication_failed());
    }
    Ok(())
}

fn consume_refused_response(
    response: ureq::http::Response<ureq::Body>,
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<(), BackendError> {
    if response.status() != 401
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(authentication_failed());
    }
    let limit = limits
        .git()
        .max_advertisement_bytes()
        .min(budget.remaining_response_bytes);
    if let Some(value) = response.headers().get("content-length") {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(authentication_failed)?;
        if length > limit {
            return Err(limit_exceeded());
        }
    }
    let mut bytes = Vec::new();
    let mut reader = response.into_body().into_reader().take(limit + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| transport_failed())?;
    if bytes.len() as u64 > limit {
        return Err(limit_exceeded());
    }
    budget.charge_response(bytes.len() as u64)
}

fn basic_authorization(credential: GitBasicCredential) -> Result<Zeroizing<String>, BackendError> {
    let input_len = credential
        .username
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(credential.token.len()))
        .ok_or_else(authentication_failed)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(input_len)
        .map_err(|_| authentication_failed())?;
    input.extend_from_slice(credential.username.as_bytes());
    input.push(b':');
    input.extend_from_slice(credential.token.as_bytes());
    let encoded_len = input_len
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(authentication_failed)?;
    let mut output = Zeroizing::new(String::new());
    output
        .try_reserve_exact(6 + encoded_len)
        .map_err(|_| authentication_failed())?;
    output.push_str("Basic ");
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    input.zeroize();
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketLine<'a> {
    Data(&'a [u8]),
    Flush,
    Delimiter,
    ResponseEnd,
}

struct PacketCursor<'a, 'budget> {
    input: &'a [u8],
    offset: usize,
    remaining_records: &'budget mut usize,
}

impl<'a, 'budget> PacketCursor<'a, 'budget> {
    const fn new(input: &'a [u8], remaining_records: &'budget mut usize) -> Self {
        Self {
            input,
            offset: 0,
            remaining_records,
        }
    }

    fn next(&mut self) -> Result<Option<PacketLine<'a>>, BackendError> {
        if self.offset == self.input.len() {
            return Ok(None);
        }
        if *self.remaining_records == 0 || self.input.len().saturating_sub(self.offset) < 4 {
            return Err(invalid_protocol());
        }
        *self.remaining_records -= 1;
        let header = &self.input[self.offset..self.offset + 4];
        let length = parse_hex_length(header)?;
        self.offset += 4;
        match length {
            0 => Ok(Some(PacketLine::Flush)),
            1 => Ok(Some(PacketLine::Delimiter)),
            2 => Ok(Some(PacketLine::ResponseEnd)),
            3 => Err(invalid_protocol()),
            length => {
                if !(4..=MAX_PACKET_LINE_BYTES).contains(&length) {
                    return Err(invalid_protocol());
                }
                let payload_len = length - 4;
                let end = self
                    .offset
                    .checked_add(payload_len)
                    .ok_or_else(invalid_protocol)?;
                let payload = self
                    .input
                    .get(self.offset..end)
                    .ok_or_else(invalid_protocol)?;
                self.offset = end;
                Ok(Some(PacketLine::Data(payload)))
            }
        }
    }
}

pub(crate) fn parse_hex_length(header: &[u8]) -> Result<usize, BackendError> {
    let mut value = 0_usize;
    for byte in header {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' => usize::from(byte - b'a' + 10),
            b'A'..=b'F' => usize::from(byte - b'A' + 10),
            _ => return Err(invalid_protocol()),
        };
        value = value
            .checked_mul(16)
            .and_then(|current| current.checked_add(digit))
            .ok_or_else(invalid_protocol)?;
    }
    Ok(value)
}

#[derive(Debug, Eq, PartialEq)]
struct Advertisement {
    selected: Option<ObjectId>,
    capabilities: BTreeSet<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum AdvertisementPrefix<'a> {
    HttpService(&'a [u8]),
    Ssh,
}

fn parse_advertisement(
    input: &[u8],
    service: &[u8],
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<Advertisement, BackendError> {
    parse_prefixed_advertisement(
        input,
        AdvertisementPrefix::HttpService(service),
        limits,
        budget,
    )
}

fn parse_ssh_advertisement(
    input: &[u8],
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<Advertisement, BackendError> {
    parse_prefixed_advertisement(input, AdvertisementPrefix::Ssh, limits, budget)
}

fn parse_prefixed_advertisement(
    input: &[u8],
    prefix: AdvertisementPrefix<'_>,
    limits: SyncLimits,
    budget: &mut GitBudget,
) -> Result<Advertisement, BackendError> {
    if input.len() as u64 > limits.git().max_advertisement_bytes() {
        return Err(limit_exceeded());
    }
    let mut packets = PacketCursor::new(input, &mut budget.remaining_packet_lines);
    if let AdvertisementPrefix::HttpService(service) = prefix {
        let expected_header = [b"# service=".as_slice(), service, b"\n"].concat();
        if packets.next()? != Some(PacketLine::Data(&expected_header))
            || packets.next()? != Some(PacketLine::Flush)
        {
            return Err(invalid_protocol());
        }
    }

    let mut first = true;
    let mut names = BTreeSet::new();
    let mut selected = None;
    let mut capabilities = BTreeSet::new();
    loop {
        let Some(packet) = packets.next()? else {
            return Err(invalid_protocol());
        };
        match packet {
            PacketLine::Flush => break,
            PacketLine::Data(data) => {
                budget.remaining_advertised_refs = budget
                    .remaining_advertised_refs
                    .checked_sub(1)
                    .ok_or_else(limit_exceeded)?;
                let data = data.strip_suffix(b"\n").unwrap_or(data);
                let (record, supplied_capabilities) = if first {
                    let mut parts = data.splitn(2, |byte| *byte == 0);
                    let record = parts.next().ok_or_else(invalid_protocol)?;
                    let raw = parts.next().unwrap_or_default();
                    (record, Some(raw))
                } else {
                    if data.contains(&0) {
                        return Err(invalid_protocol());
                    }
                    (data, None)
                };
                first = false;
                if let Some(raw) = supplied_capabilities {
                    for capability in raw.split(|byte| *byte == b' ') {
                        if capability.is_empty()
                            || !capability.iter().all(|byte| (0x21..=0x7e).contains(byte))
                            || !capabilities.insert(capability.to_vec())
                        {
                            return Err(invalid_protocol());
                        }
                    }
                }
                let separator = record
                    .iter()
                    .position(|byte| *byte == b' ')
                    .ok_or_else(invalid_protocol)?;
                let (oid, name_with_separator) = record.split_at(separator);
                let name = &name_with_separator[1..];
                if oid.len() != 40
                    || name.is_empty()
                    || !name.iter().all(|byte| (0x21..=0x7e).contains(byte))
                    || !names.insert(name.to_vec())
                {
                    return Err(invalid_protocol());
                }
                if oid == ABSENT_OID && name == b"capabilities^{}" {
                    continue;
                }
                if name.ends_with(b"^{}") {
                    return Err(invalid_protocol());
                }
                let oid = ObjectId::from_hex(oid).map_err(|_| invalid_protocol())?;
                if name == FIXED_REF && selected.replace(oid).is_some() {
                    return Err(invalid_protocol());
                }
            }
            PacketLine::Delimiter | PacketLine::ResponseEnd => return Err(invalid_protocol()),
        }
    }
    if packets.next()?.is_some() {
        return Err(invalid_protocol());
    }
    // Server metadata such as symref and agent is inert: authority is always the exact fixed ref.
    if capabilities.iter().any(|capability| {
        capability.starts_with(b"object-format=") && capability != b"object-format=sha1"
    }) {
        return Err(invalid_protocol());
    }
    Ok(Advertisement {
        selected,
        capabilities,
    })
}

const fn invalid_protocol() -> BackendError {
    BackendError::new(
        "sync_backend.git_protocol_invalid",
        "Git remote protocol response is invalid",
    )
}

const fn invalid_pack() -> BackendError {
    BackendError::new("sync_backend.git_pack_invalid", "Git pack is invalid")
}

const fn invalid_history() -> BackendError {
    BackendError::new(
        "sync_backend.git_history_invalid",
        "Git selected history is invalid",
    )
}

const fn invalid_tree() -> BackendError {
    BackendError::new(
        "sync_backend.git_tree_invalid",
        "Git selected snapshot tree is invalid",
    )
}

const fn object_mismatch() -> BackendError {
    BackendError::new(
        "sync_backend.object_mismatch",
        "supplied objects do not exactly match snapshot authority",
    )
}

const fn stale() -> BackendError {
    BackendError::new(
        "sync_backend.stale_revision",
        "remote authority no longer matches the expected revision",
    )
}

const fn intent_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.intent_invalid",
        "Git publication intent is invalid",
    )
}

pub(crate) const fn limit_exceeded() -> BackendError {
    BackendError::new(
        "sync_backend.git_limit_exceeded",
        "Git remote exceeded a configured request limit",
    )
}

const fn transport_failed() -> BackendError {
    BackendError::new(
        "sync_backend.git_transport_failed",
        "Git HTTPS transport failed safely",
    )
}

const fn authentication_failed() -> BackendError {
    BackendError::new(
        "sync_backend.git_authentication_failed",
        "Git HTTPS authentication failed safely",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitrove_model::GitSyncLimits;
    use kitrove_testkit::portable_manifest;

    #[derive(Default)]
    struct TestTree {
        files: BTreeMap<String, Vec<u8>>,
        directories: BTreeMap<String, TestTree>,
    }

    impl TestTree {
        fn insert(&mut self, path: &str, bytes: &[u8]) {
            let (name, remainder) = path.split_once('/').unwrap_or((path, ""));
            if remainder.is_empty() {
                assert!(self.files.insert(name.to_owned(), bytes.to_vec()).is_none());
            } else {
                self.directories
                    .entry(name.to_owned())
                    .or_default()
                    .insert(remainder, bytes);
            }
        }

        fn store(&self, objects: &mut GitObjectMap) -> ObjectId {
            let mut entries = Vec::new();
            for (name, bytes) in &self.files {
                entries.push((
                    name.clone(),
                    false,
                    insert_object(objects, ObjectKind::Blob, bytes),
                ));
            }
            for (name, tree) in &self.directories {
                entries.push((name.clone(), true, tree.store(objects)));
            }
            entries.sort_by(|left, right| {
                let mut left_key = left.0.clone();
                let mut right_key = right.0.clone();
                if left.1 {
                    left_key.push('/');
                }
                if right.1 {
                    right_key.push('/');
                }
                left_key.cmp(&right_key)
            });
            let mut data = Vec::new();
            for (name, directory, oid) in entries {
                data.extend_from_slice(if directory { b"40000 " } else { b"100644 " });
                data.extend_from_slice(name.as_bytes());
                data.push(0);
                data.extend_from_slice(oid.as_slice());
            }
            insert_object(objects, ObjectKind::Tree, &data)
        }
    }

    fn insert_object(objects: &mut GitObjectMap, kind: ObjectKind, data: &[u8]) -> ObjectId {
        let oid = gix_object::compute_hash(HashKind::Sha1, kind, data).unwrap();
        if let Some(existing) = objects.get(&oid) {
            assert_eq!(existing.kind, kind);
            assert_eq!(existing.data, data);
        } else {
            objects.insert(
                oid,
                GitObject {
                    kind,
                    data: data.to_vec(),
                },
            );
        }
        oid
    }

    fn commit(objects: &mut GitObjectMap, tree: ObjectId, parents: &[ObjectId]) -> ObjectId {
        let mut data = format!("tree {tree}\n");
        for parent in parents {
            data.push_str(&format!("parent {parent}\n"));
        }
        data.push_str(
            "author KitRove <kitrove@invalid> 0 +0000\ncommitter KitRove <kitrove@invalid> 0 +0000\n\nkitrove-sync-v1\n",
        );
        insert_object(objects, ObjectKind::Commit, data.as_bytes())
    }

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let length = payload.len() + 4;
        assert!(length <= MAX_PACKET_LINE_BYTES);
        let mut output = format!("{length:04x}").into_bytes();
        output.extend_from_slice(payload);
        output
    }

    fn advertisement(refs: &[&[u8]]) -> Vec<u8> {
        service_advertisement(b"git-upload-pack", refs)
    }

    fn service_advertisement(service: &[u8], refs: &[&[u8]]) -> Vec<u8> {
        let mut header = b"# service=".to_vec();
        header.extend_from_slice(service);
        header.push(b'\n');
        let mut output = pkt(&header);
        output.extend_from_slice(b"0000");
        for record in refs {
            output.extend(pkt(record));
        }
        output.extend_from_slice(b"0000");
        output
    }

    fn ssh_advertisement(refs: &[&[u8]]) -> Vec<u8> {
        let mut output = Vec::new();
        for record in refs {
            output.extend(pkt(record));
        }
        output.extend_from_slice(b"0000");
        output
    }

    struct FixtureResponse {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    const VALID_FIXTURE_CERT: &str = "308201653082010aa003020102021437f8fc084ba54ad7230de848bb913a6fbc7b94b7300a06082a8648ce3d0403023021311f301d06035504030c16726367656e2073656c66207369676e656420636572743020170d3735303130313030303030305a180f34303936303130313030303030305a3021311f301d06035504030c16726367656e2073656c66207369676e656420636572743059301306072a8648ce3d020106082a8648ce3d03010703420004991e3d576199752ac1626a4b3c02593842267a5f4f8ba298047cf1d19da66f1f387fde353b640d4f5d3f47fd12306331d98f6f9a3acc118fcbb43793e9f1f79ea31e301c301a0603551d1104133011820f666978747572652e696e76616c6964300a06082a8648ce3d0403020349003046022100aa2c5c1965206565b6ac35b2bca060173d098706b79cc56dcb224c72f20dea50022100b7448f5ce6c0b7637b6b61efc26fe1bc088b7fb35df22efbeb1ca4e855b59b95";
    const VALID_FIXTURE_KEY: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420f7d859d2aee825fcce2da2b9c1a99bf04db71386d95562caa2b9dba599fc0c03a14403420004991e3d576199752ac1626a4b3c02593842267a5f4f8ba298047cf1d19da66f1f387fde353b640d4f5d3f47fd12306331d98f6f9a3acc118fcbb43793e9f1f79e";
    const EXPIRED_FIXTURE_CERT: &str = "3082016230820108a0030201020214491013b152c1bf464df53eb76c5c7e9b4f1adb3b300a06082a8648ce3d0403023021311f301d06035504030c16726367656e2073656c66207369676e65642063657274301e170d3030303130313030303030305a170d3031303130313030303030305a3021311f301d06035504030c16726367656e2073656c66207369676e656420636572743059301306072a8648ce3d020106082a8648ce3d03010703420004ad12103c29512e69a5d95bb27079b88d63b7e16390c59dd6be2b08fda3b4e1d7ede21abfe8eefdf32766db1bfa5abeba31b368c32193964f78c0de60662e71fca31e301c301a0603551d1104133011820f666978747572652e696e76616c6964300a06082a8648ce3d04030203480030450221009c371b6504f941ecbf431fb5b25139fd1c745f6db8ab8e0d836544dd10ee5fcb022075cb54e28ae8d1945a4dfde2e4a6e9444acd008b2a04fa6c5040474d215f23dc";
    const EXPIRED_FIXTURE_KEY: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104206b14e426a8a9ab5013ec1353082b3e4ec26b28c0c3062b23e347e6a60b0aa82fa14403420004ad12103c29512e69a5d95bb27079b88d63b7e16390c59dd6be2b08fda3b4e1d7ede21abfe8eefdf32766db1bfa5abeba31b368c32193964f78c0de60662e71fc";

    fn fixture_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("fixture hex is invalid"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn spawn_https_fixture(
        responses: Vec<FixtureResponse>,
    ) -> (
        std::net::SocketAddr,
        ureq::tls::Certificate<'static>,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        spawn_https_fixture_with_material(responses, VALID_FIXTURE_CERT, VALID_FIXTURE_KEY)
    }

    fn spawn_https_fixture_with_material(
        responses: Vec<FixtureResponse>,
        certificate_hex: &str,
        private_key_hex: &str,
    ) -> (
        std::net::SocketAddr,
        ureq::tls::Certificate<'static>,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        let certificate_bytes = fixture_bytes(certificate_hex);
        let root = ureq::tls::Certificate::from_der(&certificate_bytes).to_owned();
        let certificate = rustls::pki_types::CertificateDer::from(certificate_bytes);
        let private_key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(fixture_bytes(private_key_hex));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key.into())
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let server_config = Arc::new(server_config);
            for response in responses {
                if response.status == "expect-no-request" {
                    listener.set_nonblocking(true).unwrap();
                    let until = Instant::now() + Duration::from_millis(300);
                    while Instant::now() < until {
                        match listener.accept() {
                            Ok(_) => {
                                sender
                                    .send(b"unexpected follow-up request".to_vec())
                                    .unwrap();
                                return;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("fixture accept failed unexpectedly: {error}"),
                        }
                    }
                    return;
                }
                let (stream, _) = listener.accept().unwrap();
                let connection = rustls::ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while request.len() <= 32 * 1024 {
                    if stream.read_exact(&mut byte).is_err() {
                        return;
                    }
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(request.ends_with(b"\r\n\r\n"));
                let content_length = String::from_utf8_lossy(&request)
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let header_length = request.len();
                request.resize(header_length + content_length, 0);
                if stream.read_exact(&mut request[header_length..]).is_err() {
                    return;
                }
                sender.send(request).unwrap();
                if response.status.is_empty() {
                    return;
                }
                let (delay, raw_status) =
                    if let Some(status) = response.status.strip_prefix("delayed950:") {
                        (Some(Duration::from_millis(950)), status)
                    } else if let Some(status) = response.status.strip_prefix("delayed:") {
                        (Some(Duration::from_millis(100)), status)
                    } else if let Some(status) = response.status.strip_prefix("delayed30:") {
                        (Some(Duration::from_millis(30)), status)
                    } else {
                        (None, response.status)
                    };
                if let Some(delay) = delay {
                    std::thread::sleep(delay);
                }
                let truncated_chunked_status = raw_status.strip_prefix("truncated-chunked:");
                let chunked_status =
                    truncated_chunked_status.or_else(|| raw_status.strip_prefix("chunked:"));
                let status = chunked_status.unwrap_or(raw_status);
                let mut head = if chunked_status.is_some() {
                    format!(
                        "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
                    )
                } else {
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.body.len()
                    )
                };
                for (name, value) in response.headers {
                    head.push_str(name);
                    head.push_str(": ");
                    head.push_str(value);
                    head.push_str("\r\n");
                }
                head.push_str("\r\n");
                let write_result = (|| -> std::io::Result<()> {
                    stream.write_all(head.as_bytes())?;
                    if truncated_chunked_status.is_some() {
                        write!(stream, "{:x}\r\n", response.body.len() + 1)?;
                        stream.write_all(&response.body)?;
                    } else if chunked_status.is_some() {
                        for chunk in response.body.chunks(7) {
                            write!(stream, "{:x}\r\n", chunk.len())?;
                            stream.write_all(chunk)?;
                            stream.write_all(b"\r\n")?;
                        }
                        stream.write_all(b"0\r\n\r\n")?;
                    } else {
                        stream.write_all(&response.body)?;
                    }
                    stream.flush()
                })();
                if let Err(error) = write_result {
                    if delay.is_none() && !is_expected_peer_disconnect(&error) {
                        panic!("fixture response write failed unexpectedly: {error}");
                    }
                    return;
                }
            }
        });
        (address, root, receiver, handle)
    }

    fn is_expected_peer_disconnect(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
        )
    }

    struct GitContractFixture {
        backend: GitSyncBackend,
        _requests: std::sync::mpsc::Receiver<Vec<u8>>,
    }

    fn git_contract_fixture() -> (GitContractFixture, std::thread::JoinHandle<()>) {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let absent_upload = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let absent_receive = service_advertisement(
            b"git-receive-pack",
            &[
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ],
        );
        let selected_oid = constructed.commit_oid.to_string();
        let selected_record = [
            selected_oid.as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let selected_upload = advertisement(&[&selected_record]);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&constructed.pack);
        let mut receive_status = pkt(b"unpack ok\n");
        receive_status.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        receive_status.extend_from_slice(b"0000");
        let upload_advertisement_response = |body: Vec<u8>| FixtureResponse {
            status: "200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body,
        };
        let upload_result_response = || FixtureResponse {
            status: "200 OK",
            headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
            body: upload_response.clone(),
        };
        let responses = vec![
            upload_advertisement_response(absent_upload.clone()),
            upload_advertisement_response(absent_upload),
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-receive-pack-advertisement",
                )],
                body: absent_receive,
            },
            FixtureResponse {
                status: "200 OK",
                headers: vec![("Content-Type", "application/x-git-receive-pack-result")],
                body: receive_status,
            },
            upload_advertisement_response(selected_upload.clone()),
            upload_result_response(),
            upload_advertisement_response(selected_upload.clone()),
            upload_result_response(),
            upload_advertisement_response(selected_upload),
            upload_result_response(),
        ];
        let (address, root, requests, server) = spawn_https_fixture(responses);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        (
            GitContractFixture {
                backend,
                _requests: requests,
            },
            server,
        )
    }

    impl crate::sync_backend::tests::BackendContractFixture for GitContractFixture {
        type Backend = GitSyncBackend;

        fn backend(&self) -> &Self::Backend {
            &self.backend
        }

        fn assert_exact_fetch_and_immutable_rules(&self) {
            selected_commit_tree_reconstructs_and_verifies_exact_snapshot_objects();
        }

        fn assert_aba_and_selected_history_rules(&self) {
            reconciliation_requires_selected_history_or_the_exact_expected_revision();
        }

        fn assert_publication_interruption_rules(&self) {
            receive_request_is_exact_and_status_requires_one_complete_acknowledgement();
        }

        fn assert_alias_and_hostile_filesystem_rules(&self) {
            test_only_connector_preserves_canonical_remote_identity();
        }

        fn assert_aggregate_limit_rules(&self) {
            pack_decoder_verifies_hashes_kinds_and_exact_boundaries();
        }

        fn assert_redaction_rules(&self) {
            basic_authentication_is_canonical_bounded_and_challenge_gated();
        }
    }

    fn parse_test_advertisement(
        input: &[u8],
        limits: SyncLimits,
    ) -> Result<Advertisement, BackendError> {
        let mut budget = GitBudget::new(limits);
        parse_advertisement(input, b"git-upload-pack", limits, &mut budget)
    }

    fn tiny_git(max_advertisement_bytes: u64, max_refs: usize, max_packets: usize) -> SyncLimits {
        let git = GitSyncLimits::new(
            1,
            1,
            1,
            max_advertisement_bytes.max(2),
            1,
            max_advertisement_bytes,
            max_refs,
            max_packets,
            2,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn advertisement_limits(max_advertisement_bytes: u64) -> SyncLimits {
        advertisement_shape_limits(
            max_advertisement_bytes,
            SyncLimits::default().git().max_advertisement_refs(),
        )
    }

    fn advertisement_shape_limits(
        max_advertisement_bytes: u64,
        max_advertisement_refs: usize,
    ) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            defaults.max_response_header_bytes(),
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            defaults.max_response_body_bytes(),
            defaults.max_request_body_bytes(),
            max_advertisement_bytes,
            max_advertisement_refs,
            defaults.max_packet_lines(),
            defaults.max_received_pack_bytes(),
            defaults.max_decoded_objects(),
            defaults.max_decoded_object_bytes(),
            defaults.max_total_decoded_object_bytes(),
            defaults.max_delta_depth(),
            defaults.connect_timeout_ms(),
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            defaults.exchange_deadline_ms(),
            defaults.operation_deadline_ms(),
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn response_header_limits(max_response_header_bytes: usize) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            max_response_header_bytes,
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            defaults.max_response_body_bytes(),
            defaults.max_request_body_bytes(),
            defaults.max_advertisement_bytes(),
            defaults.max_advertisement_refs(),
            defaults.max_packet_lines(),
            defaults.max_received_pack_bytes(),
            defaults.max_decoded_objects(),
            defaults.max_decoded_object_bytes(),
            defaults.max_total_decoded_object_bytes(),
            defaults.max_delta_depth(),
            defaults.connect_timeout_ms(),
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            defaults.exchange_deadline_ms(),
            defaults.operation_deadline_ms(),
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn request_body_limits(max_request_body_bytes: u64) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            defaults.max_response_header_bytes(),
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            defaults.max_response_body_bytes(),
            max_request_body_bytes,
            defaults.max_advertisement_bytes(),
            defaults.max_advertisement_refs(),
            defaults.max_packet_lines(),
            defaults.max_received_pack_bytes(),
            defaults.max_decoded_objects(),
            defaults.max_decoded_object_bytes(),
            defaults.max_total_decoded_object_bytes(),
            defaults.max_delta_depth(),
            defaults.connect_timeout_ms(),
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            defaults.exchange_deadline_ms(),
            defaults.operation_deadline_ms(),
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn response_budget_limits(
        max_response_body_bytes: u64,
        max_advertisement_bytes: u64,
        max_pack_bytes: u64,
    ) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            defaults.max_response_header_bytes(),
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            max_response_body_bytes,
            defaults.max_request_body_bytes(),
            max_advertisement_bytes,
            defaults.max_advertisement_refs(),
            defaults.max_packet_lines(),
            max_pack_bytes,
            defaults.max_decoded_objects(),
            defaults.max_decoded_object_bytes(),
            defaults.max_total_decoded_object_bytes(),
            defaults.max_delta_depth(),
            defaults.connect_timeout_ms(),
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            defaults.exchange_deadline_ms(),
            defaults.operation_deadline_ms(),
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn pack_limits(
        max_pack_bytes: u64,
        max_objects: usize,
        max_object_bytes: u64,
        max_total_bytes: u64,
    ) -> SyncLimits {
        pack_shape_limits(
            max_pack_bytes,
            max_objects,
            max_object_bytes,
            max_total_bytes,
            SyncLimits::default().git().max_delta_depth(),
        )
    }

    fn pack_shape_limits(
        max_pack_bytes: u64,
        max_objects: usize,
        max_object_bytes: u64,
        max_total_bytes: u64,
        max_delta_depth: usize,
    ) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            defaults.max_response_header_bytes(),
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            max_pack_bytes.max(defaults.max_response_body_bytes()),
            defaults.max_request_body_bytes(),
            defaults.max_advertisement_bytes(),
            defaults.max_advertisement_refs(),
            defaults.max_packet_lines(),
            max_pack_bytes,
            max_objects,
            max_object_bytes,
            max_total_bytes,
            max_delta_depth,
            defaults.connect_timeout_ms(),
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            defaults.exchange_deadline_ms(),
            defaults.operation_deadline_ms(),
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn timeout_limits() -> SyncLimits {
        timeout_shape_limits(20, 50, 100)
    }

    fn timeout_shape_limits(
        response_timeout_ms: u64,
        exchange_deadline_ms: u64,
        operation_deadline_ms: u64,
    ) -> SyncLimits {
        let defaults = SyncLimits::default().git();
        let git = GitSyncLimits::new(
            defaults.max_response_header_bytes(),
            defaults.http_input_buffer_bytes(),
            defaults.http_output_buffer_bytes(),
            defaults.max_response_body_bytes(),
            defaults.max_request_body_bytes(),
            defaults.max_advertisement_bytes(),
            defaults.max_advertisement_refs(),
            defaults.max_packet_lines(),
            defaults.max_received_pack_bytes(),
            defaults.max_decoded_objects(),
            defaults.max_decoded_object_bytes(),
            defaults.max_total_decoded_object_bytes(),
            defaults.max_delta_depth(),
            defaults.connect_timeout_ms(),
            response_timeout_ms,
            response_timeout_ms,
            exchange_deadline_ms,
            operation_deadline_ms,
        )
        .unwrap();
        SyncLimits::default().with_git_limits(git)
    }

    fn history_limits(max_history: usize) -> SyncLimits {
        let limits = SyncLimits::default();
        SyncLimits::new(
            limits.max_snapshot_bytes(),
            limits.max_control_bytes(),
            limits.max_manifest_bytes(),
            limits.max_lock_bytes(),
            limits.max_object_count(),
            limits.max_object_bytes(),
            limits.max_total_object_bytes(),
            limits.max_conflicts(),
            limits.max_components(),
            max_history,
        )
        .unwrap()
        .with_git_limits(limits.git())
    }

    fn write_bytes(writer: &mut impl std::io::Write, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let written = writer.write(bytes).unwrap();
            assert_ne!(written, 0);
            bytes = &bytes[written..];
        }
    }

    fn test_pack(objects: &[(ObjectKind, &[u8])]) -> Vec<u8> {
        let count = u32::try_from(objects.len()).unwrap();
        let mut pack = gix_pack::data::header::encode(gix_pack::data::Version::V2, count).to_vec();
        for (kind, data) in objects {
            let header = match kind {
                ObjectKind::Commit => gix_pack::data::entry::Header::Commit,
                ObjectKind::Tree => gix_pack::data::entry::Header::Tree,
                ObjectKind::Blob => gix_pack::data::entry::Header::Blob,
                ObjectKind::Tag => gix_pack::data::entry::Header::Tag,
            };
            header
                .write_to(u64::try_from(data.len()).unwrap(), &mut pack)
                .unwrap();
            let mut deflate =
                gix_zlib::stream::deflate::Write::new(pack, gix_zlib::Compression::DEFAULT);
            write_bytes(&mut deflate, data);
            deflate.flush().unwrap();
            pack = deflate.into_inner();
        }
        let mut hasher = gix_hash::hasher(HashKind::Sha1);
        hasher.update(&pack);
        let checksum = hasher.try_finalize().unwrap();
        pack.extend_from_slice(checksum.as_slice());
        pack
    }

    fn chained_delta_pack() -> Vec<u8> {
        fn literal_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
            assert!(base.len() < 128 && target.len() < 128 && !target.is_empty());
            let mut delta = vec![base.len() as u8, target.len() as u8, target.len() as u8];
            delta.extend_from_slice(target);
            delta
        }

        fn append_compressed(pack: Vec<u8>, data: &[u8]) -> Vec<u8> {
            let mut deflate =
                gix_zlib::stream::deflate::Write::new(pack, gix_zlib::Compression::DEFAULT);
            write_bytes(&mut deflate, data);
            deflate.flush().unwrap();
            deflate.into_inner()
        }

        let base = b"base payload\n";
        let child = b"child payload\n";
        let grandchild = b"grandchild payload\n";
        let mut pack = gix_pack::data::header::encode(gix_pack::data::Version::V2, 3).to_vec();
        let base_offset = pack.len();
        gix_pack::data::entry::Header::Blob
            .write_to(base.len() as u64, &mut pack)
            .unwrap();
        pack = append_compressed(pack, base);

        let child_offset = pack.len();
        let child_delta = literal_delta(base, child);
        gix_pack::data::entry::Header::OfsDelta {
            base_distance: (child_offset - base_offset) as u64,
        }
        .write_to(child_delta.len() as u64, &mut pack)
        .unwrap();
        pack = append_compressed(pack, &child_delta);

        let grandchild_offset = pack.len();
        let grandchild_delta = literal_delta(child, grandchild);
        gix_pack::data::entry::Header::OfsDelta {
            base_distance: (grandchild_offset - child_offset) as u64,
        }
        .write_to(grandchild_delta.len() as u64, &mut pack)
        .unwrap();
        pack = append_compressed(pack, &grandchild_delta);

        let mut hasher = gix_hash::hasher(HashKind::Sha1);
        hasher.update(&pack);
        let checksum = hasher.try_finalize().unwrap();
        pack.extend_from_slice(checksum.as_slice());
        pack
    }

    #[test]
    fn backend_configuration_disables_ambient_and_cross_origin_http_behavior() {
        let backend =
            GitSyncBackend::open("https://example.com/owner/repo.git", SyncLimits::default())
                .unwrap();
        let config = backend.agent.config();
        assert!(config.https_only());
        assert!(!config.http_status_as_error());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert_eq!(config.max_response_header_size(), 32 * 1024);
        assert_eq!(config.input_buffer_size(), 8 * 1024);
        assert_eq!(config.output_buffer_size(), 8 * 1024);
        assert_eq!(config.tls_config().provider(), TlsProvider::Rustls);
        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::WebPki
        ));
    }

    #[test]
    fn test_only_connector_preserves_canonical_remote_identity() {
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            ureq::tls::Certificate::from_der(&[0]).to_owned(),
            "127.0.0.1:1".parse().unwrap(),
            None,
        )
        .unwrap();
        let debug = format!("{backend:?}");
        assert!(!debug.contains("fixture.invalid"));
        assert!(!debug.contains("owner"));
    }

    #[test]
    fn integrated_https_fixture_preserves_origin_and_retries_basic_once() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "401 Unauthorized",
                headers: vec![("WWW-Authenticate", "Basic realm=\"kitrove\"")],
                body: b"refused".to_vec(),
            },
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: absent,
            },
        ]);
        let prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let prompt_count = Arc::clone(&prompts);
        let provider = GitCredentialProvider::terminal(move || {
            prompt_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(
                GitBasicCredential::new("fixture-user".to_owned(), "fixture-token".to_owned())
                    .unwrap(),
            )
        });
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            Some(provider),
        )
        .unwrap();
        assert!(
            backend
                .inspect(SyncLimits::default())
                .unwrap()
                .snapshot()
                .is_none()
        );
        assert_eq!(prompts.load(std::sync::atomic::Ordering::SeqCst), 1);

        let first = String::from_utf8(requests.recv().unwrap()).unwrap();
        let second = String::from_utf8(requests.recv().unwrap()).unwrap();
        server.join().unwrap();
        for request in [&first, &second] {
            assert!(
                request.starts_with(
                    "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
                )
            );
            assert!(request.contains("\r\nhost: fixture.invalid\r\n"));
        }
        assert!(!first.to_ascii_lowercase().contains("authorization:"));
        assert!(
            second.contains("\r\nauthorization: Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtdG9rZW4=\r\n")
        );
        let debug = format!("{backend:?}");
        assert!(!debug.contains("fixture-user"));
        assert!(!debug.contains("fixture-token"));
    }

    #[test]
    fn credentials_are_reprompted_at_each_operation_boundary() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let unauthorized = || FixtureResponse {
            status: "401 Unauthorized",
            headers: vec![("WWW-Authenticate", "Basic realm=\"fixture\"")],
            body: Vec::new(),
        };
        let accepted = || FixtureResponse {
            status: "200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body: absent.clone(),
        };
        let (address, root, requests, server) =
            spawn_https_fixture(vec![unauthorized(), accepted(), unauthorized(), accepted()]);
        let prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_prompts = Arc::clone(&prompts);
        let provider = GitCredentialProvider::terminal(move || {
            observed_prompts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(GitBasicCredential::new("operator".to_owned(), "token".to_owned()).unwrap())
        });
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            Some(provider),
        )
        .unwrap();
        backend.inspect(SyncLimits::default()).unwrap();
        backend.inspect(SyncLimits::default()).unwrap();
        assert_eq!(prompts.load(std::sync::atomic::Ordering::SeqCst), 2);

        let request_list: Vec<_> = (0..4).map(|_| requests.recv().unwrap()).collect();
        server.join().unwrap();
        for index in [0, 2] {
            assert!(
                !request_list[index]
                    .windows(b"Authorization:".len())
                    .any(|window| window.eq_ignore_ascii_case(b"Authorization:"))
            );
        }
        for index in [1, 3] {
            assert!(
                request_list[index]
                    .windows(b"Authorization: Basic ".len())
                    .any(|window| window.eq_ignore_ascii_case(b"Authorization: Basic "))
            );
        }
    }

    #[test]
    fn satisfies_shared_backend_contract_through_smart_https() {
        let (fixture, server) = git_contract_fixture();
        crate::sync_backend::tests::assert_backend_contract(&fixture);
        server.join().unwrap();
    }

    #[test]
    fn integrated_https_fixture_accepts_anonymous_and_refuses_auth_confusion() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body: absent,
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_ok());
        let request = String::from_utf8(requests.recv().unwrap()).unwrap();
        server.join().unwrap();
        assert!(!request.to_ascii_lowercase().contains("authorization:"));

        for challenges in [
            vec![("WWW-Authenticate", "Basic realm=\"kitrove\"")],
            vec![("WWW-Authenticate", "Bearer realm=\"kitrove\"")],
            vec![
                ("WWW-Authenticate", "Basic realm=\"kitrove\""),
                ("WWW-Authenticate", "Basic realm=\"other\""),
            ],
        ] {
            let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
                status: "401 Unauthorized",
                headers: challenges,
                body: b"refused".to_vec(),
            }]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                SyncLimits::default(),
                root,
                address,
                None,
            )
            .unwrap();
            assert!(backend.inspect(SyncLimits::default()).is_err());
            let request = String::from_utf8(requests.recv().unwrap()).unwrap();
            server.join().unwrap();
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
        }
    }

    #[test]
    fn git_network_and_credential_canaries_never_cross_error_or_debug_surfaces() {
        let url_canary = "d4-url-canary-41a9";
        let username_canary = "D4-USERNAME-CANARY-52ba";
        let token_canary = "D4-TOKEN-CANARY-63cb";
        let certificate_canary = &VALID_FIXTURE_CERT[..24];
        let status_canary = "D4-SERVER-STATUS-CANARY-74dc";
        let ref_canary = "refs/heads/D4-REF-CANARY-85ed";
        let packet_canary = "D4-PACKET-CANARY-96fe";
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "401 Unauthorized",
                headers: vec![("WWW-Authenticate", "Basic realm=\"fixture\"")],
                body: Vec::new(),
            },
            FixtureResponse {
                status: "401 D4-SERVER-STATUS-CANARY-74dc",
                headers: Vec::new(),
                body: format!("{ref_canary}\n{packet_canary}").into_bytes(),
            },
        ]);
        let username = username_canary.to_owned();
        let token = token_canary.to_owned();
        let provider = GitCredentialProvider::terminal(move || {
            Some(GitBasicCredential::new(username.clone(), token.clone()).unwrap())
        });
        let backend = GitSyncBackend::open_for_test(
            &format!("https://fixture.invalid/{url_canary}/repo.git"),
            SyncLimits::default(),
            root,
            address,
            Some(provider),
        )
        .unwrap();
        let error = backend.inspect(SyncLimits::default()).unwrap_err();
        let surface = format!("{backend:?} {error:?} {error}");
        for canary in [
            url_canary,
            username_canary,
            token_canary,
            certificate_canary,
            status_canary,
            ref_canary,
            packet_canary,
        ] {
            assert!(!surface.contains(canary));
        }
        let _ = requests.recv().unwrap();
        let _ = requests.recv().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn integrated_https_fixture_refuses_retry_exhaustion_redirects_and_tls_mismatch() {
        let prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let prompt_count = Arc::clone(&prompts);
        let provider = GitCredentialProvider::terminal(move || {
            prompt_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(GitBasicCredential::new("user".to_owned(), "token".to_owned()).unwrap())
        });
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "401 Unauthorized",
                headers: vec![("WWW-Authenticate", "Basic realm=\"kitrove\"")],
                body: Vec::new(),
            },
            FixtureResponse {
                status: "401 Unauthorized",
                headers: vec![("WWW-Authenticate", "Basic realm=\"kitrove\"")],
                body: Vec::new(),
            },
        ]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            Some(provider),
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_err());
        let _ = requests.recv().unwrap();
        let _ = requests.recv().unwrap();
        server.join().unwrap();
        assert_eq!(prompts.load(std::sync::atomic::Ordering::SeqCst), 1);

        for location in [
            "https://fixture.invalid/other.git",
            "https://other.invalid/owner/repo.git",
        ] {
            let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
                status: "302 Found",
                headers: vec![("Location", location)],
                body: Vec::new(),
            }]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                SyncLimits::default(),
                root,
                address,
                None,
            )
            .unwrap();
            assert!(backend.inspect(SyncLimits::default()).is_err());
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }

        let (address, root, _requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "200 OK",
            headers: Vec::new(),
            body: Vec::new(),
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://other.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_err());
        server.join().unwrap();

        let (address, _root, _requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "200 OK",
            headers: Vec::new(),
            body: Vec::new(),
        }]);
        let wrong_root =
            ureq::tls::Certificate::from_der(&fixture_bytes(EXPIRED_FIXTURE_CERT)).to_owned();
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            wrong_root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_err());
        server.join().unwrap();

        let (address, root, _requests, server) = spawn_https_fixture_with_material(
            vec![FixtureResponse {
                status: "200 OK",
                headers: Vec::new(),
                body: Vec::new(),
            }],
            EXPIRED_FIXTURE_CERT,
            EXPIRED_FIXTURE_KEY,
        );
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_err());
        server.join().unwrap();
    }

    #[test]
    fn integrated_https_fixture_publishes_an_exact_old_receive_pack() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let receive_advertisement = service_advertisement(
            b"git-receive-pack",
            &[
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ],
        );
        let mut status = pkt(b"unpack ok\n");
        status.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        status.extend_from_slice(b"0000");
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-receive-pack-advertisement",
                )],
                body: receive_advertisement,
            },
            FixtureResponse {
                status: "200 OK",
                headers: vec![("Content-Type", "application/x-git-receive-pack-result")],
                body: status,
            },
        ]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert_eq!(
            backend.publish(&intent, &snapshot, &[], limits).unwrap(),
            PublicationStatus::Published(intent.proposed_revision().clone())
        );

        let advertisement_request = requests.recv().unwrap();
        let receive_request = requests.recv().unwrap();
        server.join().unwrap();
        assert!(
            advertisement_request.starts_with(
                b"GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n"
            )
        );
        let header_end = receive_request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap();
        assert!(receive_request.starts_with(b"POST /owner/repo.git/git-receive-pack HTTP/1.1\r\n"));
        let body = &receive_request[header_end..];
        let mut remaining = limits.git().max_packet_lines();
        let mut packets = PacketCursor::new(body, &mut remaining);
        let parsed: GitPublicationIntentV1 = serde_json::from_str(intent.as_persisted()).unwrap();
        let command = format!(
            "{} {} refs/heads/kitrove-sync-v1\0report-status\n",
            ObjectId::null(HashKind::Sha1),
            parsed.commit_oid
        );
        assert_eq!(
            packets.next().unwrap(),
            Some(PacketLine::Data(command.as_bytes()))
        );
        assert_eq!(packets.next().unwrap(), Some(PacketLine::Flush));
        assert_eq!(&body[packets.offset..4 + packets.offset], b"PACK");
    }

    #[test]
    fn integrated_receive_status_failures_never_claim_publication() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "d".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let advertisement = service_advertisement(
            b"git-receive-pack",
            &[
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ],
        );
        let mut unpack_failed = pkt(b"unpack failed\n");
        unpack_failed.extend_from_slice(b"0000");
        let mut rejected = pkt(b"unpack ok\n");
        rejected.extend(pkt(b"ng refs/heads/kitrove-sync-v1 rejected\n"));
        rejected.extend_from_slice(b"0000");
        let mut missing_ref = pkt(b"unpack ok\n");
        missing_ref.extend_from_slice(b"0000");
        let mut wrong_ref = pkt(b"unpack ok\n");
        wrong_ref.extend(pkt(b"ok refs/heads/other\n"));
        wrong_ref.extend_from_slice(b"0000");
        let mut duplicate = pkt(b"unpack ok\n");
        duplicate.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        duplicate.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        duplicate.extend_from_slice(b"0000");

        for status in [
            unpack_failed,
            rejected,
            missing_ref,
            wrong_ref,
            duplicate,
            b"0008abc".to_vec(),
        ] {
            let (address, root, requests, server) = spawn_https_fixture(vec![
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![(
                        "Content-Type",
                        "application/x-git-receive-pack-advertisement",
                    )],
                    body: advertisement.clone(),
                },
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "application/x-git-receive-pack-result")],
                    body: status,
                },
            ]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(
                backend.publish(&intent, &snapshot, &[], limits).unwrap(),
                PublicationStatus::Uncertain
            );
            let _ = requests.recv().unwrap();
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }
    }

    #[test]
    fn integrated_https_fixture_reports_races_and_lost_acknowledgements_as_uncertain() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "c".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();

        let raced = service_advertisement(
            b"git-receive-pack",
            &[
                b"1111111111111111111111111111111111111111 refs/heads/kitrove-sync-v1\0object-format=sha1 report-status\n",
            ],
        );
        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-receive-pack-advertisement",
            )],
            body: raced,
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert_eq!(
            backend.publish(&intent, &snapshot, &[], limits).unwrap(),
            PublicationStatus::Uncertain
        );
        let _ = requests.recv().unwrap();
        assert!(requests.try_recv().is_err());
        server.join().unwrap();

        let absent = service_advertisement(
            b"git-receive-pack",
            &[
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ],
        );
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-receive-pack-advertisement",
                )],
                body: absent,
            },
            FixtureResponse {
                status: "",
                headers: Vec::new(),
                body: Vec::new(),
            },
        ]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert_eq!(
            backend.publish(&intent, &snapshot, &[], limits).unwrap(),
            PublicationStatus::Uncertain
        );
        let _ = requests.recv().unwrap();
        let _ = requests.recv().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn integrated_https_fixture_enforces_body_boundary_and_disconnect_failure() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        for (allowance, succeeds) in [
            (absent.len() as u64, true),
            (absent.len() as u64 - 1, false),
        ] {
            let limits = advertisement_limits(allowance);
            let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: absent.clone(),
            }]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(backend.inspect(limits).is_ok(), succeeds);
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }

        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "",
            headers: Vec::new(),
            body: Vec::new(),
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            SyncLimits::default(),
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(SyncLimits::default()).is_err());
        let _ = requests.recv().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn integrated_https_fixture_enforces_the_exact_complete_response_header_boundary() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/x-git-upload-pack-advertisement\r\n\r\n",
            absent.len()
        );
        for (allowance, succeeds) in [(head.len(), true), (head.len() - 1, false)] {
            let limits = response_header_limits(allowance);
            let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: absent.clone(),
            }]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(backend.inspect(limits).is_ok(), succeeds);
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }
    }

    #[test]
    fn integrated_https_fixture_enforces_the_aggregate_multi_exchange_response_budget() {
        let defaults = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), defaults).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "d".repeat(64))).unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            defaults,
        )
        .unwrap();
        let selected_oid = constructed.commit_oid.to_string();
        let selected_record = [
            selected_oid.as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let selected_upload = advertisement(&[&selected_record]);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&constructed.pack);
        let exact_total = (selected_upload.len() + upload_response.len()) as u64;

        for (allowance, succeeds) in [(exact_total, true), (exact_total - 1, false)] {
            let limits = response_budget_limits(
                allowance,
                selected_upload.len() as u64,
                constructed.pack.len() as u64,
            );
            let (address, root, requests, server) = spawn_https_fixture(vec![
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![(
                        "Content-Type",
                        "application/x-git-upload-pack-advertisement",
                    )],
                    body: selected_upload.clone(),
                },
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
                    body: upload_response.clone(),
                },
            ]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(backend.inspect(limits).is_ok(), succeeds);
            let _ = requests.recv().unwrap();
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }
    }

    #[test]
    fn integrated_https_fixture_enforces_the_upload_request_body_boundary() {
        let defaults = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), defaults).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "e".repeat(64))).unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            defaults,
        )
        .unwrap();
        let capabilities = [
            b"object-format=sha1".to_vec(),
            b"shallow".to_vec(),
            b"no-progress".to_vec(),
            b"ofs-delta".to_vec(),
        ]
        .into_iter()
        .collect();
        let exact_request =
            build_upload_request(constructed.commit_oid, &capabilities, defaults).unwrap();
        let selected_oid = constructed.commit_oid.to_string();
        let selected_record = [
            selected_oid.as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let selected_upload = advertisement(&[&selected_record]);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&constructed.pack);

        for (allowance, succeeds) in [
            (exact_request.len() as u64, true),
            (exact_request.len() as u64 - 1, false),
        ] {
            let limits = request_body_limits(allowance);
            let mut responses = vec![FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: selected_upload.clone(),
            }];
            if succeeds {
                responses.push(FixtureResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
                    body: upload_response.clone(),
                });
            }
            let (address, root, requests, server) = spawn_https_fixture(responses);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(backend.inspect(limits).is_ok(), succeeds);
            let _ = requests.recv().unwrap();
            if succeeds {
                let upload_request = requests.recv().unwrap();
                let header_end = upload_request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .unwrap();
                assert_eq!(&upload_request[header_end..], exact_request);
            } else {
                assert!(requests.try_recv().is_err());
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn integrated_https_fixture_enforces_the_receive_request_body_boundary() {
        let defaults = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), defaults).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "f".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            defaults,
        )
        .unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            defaults,
        )
        .unwrap();
        let exact_request = build_receive_request(
            constructed.expected_oid,
            constructed.commit_oid,
            &constructed.pack,
            defaults,
        )
        .unwrap();
        let absent_receive = service_advertisement(
            b"git-receive-pack",
            &[
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ],
        );
        let mut receive_status = pkt(b"unpack ok\n");
        receive_status.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        receive_status.extend_from_slice(b"0000");

        for (allowance, succeeds) in [
            (exact_request.len() as u64, true),
            (exact_request.len() as u64 - 1, false),
        ] {
            let limits = request_body_limits(allowance);
            let mut responses = vec![FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-receive-pack-advertisement",
                )],
                body: absent_receive.clone(),
            }];
            if succeeds {
                responses.push(FixtureResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "application/x-git-receive-pack-result")],
                    body: receive_status.clone(),
                });
            }
            let (address, root, requests, server) = spawn_https_fixture(responses);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            let result = backend.publish(&intent, &snapshot, &[], limits);
            if succeeds {
                assert_eq!(
                    result.unwrap(),
                    PublicationStatus::Published(intent.proposed_revision().clone())
                );
            } else {
                assert!(result.is_err());
            }
            let _ = requests.recv().unwrap();
            if succeeds {
                let receive_request = requests.recv().unwrap();
                let header_end = receive_request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .unwrap();
                assert_eq!(&receive_request[header_end..], exact_request);
            } else {
                assert!(requests.try_recv().is_err());
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn hostile_advertisement_refusal_stops_before_any_follow_up_exchange() {
        let oid = b"1111111111111111111111111111111111111111";
        let hostile = advertisement(&[
            &[
                oid.as_slice(),
                b" refs/heads/unrelated-a\0object-format=sha1\n",
            ]
            .concat(),
            &[oid.as_slice(), b" refs/heads/unrelated-b\n"].concat(),
        ]);
        let limits = advertisement_shape_limits(hostile.len() as u64, 1);
        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body: hostile,
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(limits).is_err());
        let request = requests.recv().unwrap();
        assert!(
            request
                .starts_with(b"GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n")
        );
        server.join().unwrap();
        assert!(requests.try_recv().is_err());
    }

    #[test]
    fn chunked_https_body_is_decoded_through_the_same_exact_byte_boundary() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        for (allowance, succeeds) in [
            (absent.len() as u64, true),
            (absent.len() as u64 - 1, false),
        ] {
            let limits = advertisement_limits(allowance);
            let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
                status: "chunked:200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: absent.clone(),
            }]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            assert_eq!(backend.inspect(limits).is_ok(), succeeds);
            let _ = requests.recv().unwrap();
            server.join().unwrap();
        }

        let limits = advertisement_limits(absent.len() as u64);
        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "truncated-chunked:200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body: absent,
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(limits).is_err());
        let _ = requests.recv().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn stalled_https_response_is_cancelled_by_the_operation_timeouts() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        let limits = timeout_limits();
        let (address, root, requests, server) = spawn_https_fixture(vec![FixtureResponse {
            status: "delayed:200 OK",
            headers: vec![(
                "Content-Type",
                "application/x-git-upload-pack-advertisement",
            )],
            body: absent,
        }]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        let started = std::time::Instant::now();
        assert!(backend.inspect(limits).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        let _ = requests.recv().unwrap();
        assert!(requests.try_recv().is_err());
        server.join().unwrap();
    }

    #[test]
    fn authentication_retry_shares_one_complete_operation_deadline() {
        let selected = advertisement(&[
            b"1111111111111111111111111111111111111111 refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]);
        let limits = timeout_shape_limits(1_000, 1_000, 1_000);
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "delayed:401 Unauthorized",
                headers: vec![("WWW-Authenticate", "Basic realm=\"fixture\"")],
                body: Vec::new(),
            },
            FixtureResponse {
                status: "delayed950:200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: selected,
            },
            FixtureResponse {
                status: "expect-no-request",
                headers: Vec::new(),
                body: Vec::new(),
            },
        ]);
        let provider = GitCredentialProvider::terminal(|| {
            Some(GitBasicCredential::new("operator".to_owned(), "token".to_owned()).unwrap())
        });
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            Some(provider),
        )
        .unwrap();
        let started = Instant::now();
        assert!(backend.inspect(limits).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = requests.recv().unwrap();
        let _ = requests.recv().unwrap();
        server.join().unwrap();
        assert!(requests.try_recv().is_err());
    }

    #[test]
    fn integrated_https_fixture_receives_and_verifies_the_selected_snapshot() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let selected_oid = constructed.commit_oid.to_string();
        let advertised = [
            selected_oid.as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let upload_advertisement = advertisement(&[&advertised]);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&constructed.pack);
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: upload_advertisement,
            },
            FixtureResponse {
                status: "200 OK",
                headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
                body: upload_response,
            },
        ]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        let observed = backend.inspect(limits).unwrap();
        assert_eq!(observed.snapshot(), Some(&snapshot));
        assert_eq!(
            observed.revision().as_str(),
            format!("git:sha1:{}", constructed.commit_oid)
        );

        let _ = requests.recv().unwrap();
        let upload_request = requests.recv().unwrap();
        server.join().unwrap();
        let header_end = upload_request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap();
        assert!(upload_request.starts_with(b"POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n"));
        let body = &upload_request[header_end..];
        let expected = build_upload_request(
            constructed.commit_oid,
            &[
                b"object-format=sha1".to_vec(),
                b"shallow".to_vec(),
                b"no-progress".to_vec(),
                b"ofs-delta".to_vec(),
            ]
            .into_iter()
            .collect(),
            limits,
        )
        .unwrap();
        assert_eq!(body, expected);
    }

    #[test]
    fn integrated_https_fixture_refuses_a_high_ratio_selected_pack_without_disk_state() {
        let expanded = vec![b'x'; 1024 * 1024];
        let pack = test_pack(&[(ObjectKind::Blob, expanded.as_slice())]);
        let mut selected_object = GitObjectMap::new();
        let selected = insert_object(&mut selected_object, ObjectKind::Blob, &expanded);
        let selected_oid = selected.to_string();
        let advertised = [
            selected_oid.as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let upload_advertisement = advertisement(&[&advertised]);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&pack);
        let limits = pack_limits(pack.len() as u64, 1, 64 * 1024, 64 * 1024);
        let (address, root, requests, server) = spawn_https_fixture(vec![
            FixtureResponse {
                status: "200 OK",
                headers: vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                )],
                body: upload_advertisement,
            },
            FixtureResponse {
                status: "200 OK",
                headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
                body: upload_response,
            },
        ]);
        let backend = GitSyncBackend::open_for_test(
            "https://fixture.invalid/owner/repo.git",
            limits,
            root,
            address,
            None,
        )
        .unwrap();
        assert!(backend.inspect(limits).is_err());
        let _ = requests.recv().unwrap();
        let _ = requests.recv().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn poisoned_ambient_git_proxy_and_tls_environment_cannot_change_https_behavior() {
        let sandbox = tempfile::tempdir().unwrap();
        let sentinel = sandbox.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        for test in [
            "git_sync_backend::tests::integrated_https_fixture_preserves_origin_and_retries_basic_once",
            "git_sync_backend::tests::integrated_https_fixture_receives_and_verifies_the_selected_snapshot",
            "git_sync_backend::tests::integrated_https_fixture_refuses_a_high_ratio_selected_pack_without_disk_state",
        ] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test])
                .env("HTTPS_PROXY", "https://127.0.0.1:1")
                .env("HTTP_PROXY", "http://127.0.0.1:1")
                .env("ALL_PROXY", "http://127.0.0.1:1")
                .env("GIT_ASKPASS", "kitrove-forbidden-askpass")
                .env("SSH_ASKPASS", "kitrove-forbidden-ssh-askpass")
                .env("GIT_CONFIG_GLOBAL", "kitrove-forbidden-git-config")
                .env("GIT_CONFIG_SYSTEM", "kitrove-forbidden-git-system-config")
                .env("SSL_CERT_FILE", "kitrove-forbidden-cert-file")
                .env("SSL_CERT_DIR", "kitrove-forbidden-cert-directory")
                .env("TMPDIR", sandbox.path())
                .env("TMP", sandbox.path())
                .env("TEMP", sandbox.path())
                .current_dir(sandbox.path())
                .status()
                .unwrap();
            assert!(status.success());
        }
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        let entries: Vec<_> = std::fs::read_dir(sandbox.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from("sentinel")]);
    }

    #[test]
    #[ignore = "requires the public GitHub smart-HTTPS fixture"]
    fn public_github_fixture_uses_the_production_connector_and_pinned_roots() {
        let limits = SyncLimits::default();
        let backend =
            GitSyncBackend::open("https://github.com/octocat/Hello-World.git", limits).unwrap();
        let observed = backend.inspect(limits).unwrap();
        assert!(observed.snapshot().is_none());
        assert_eq!(observed.revision().as_str(), "git:absent:v1");
    }

    #[test]
    fn basic_authentication_is_canonical_bounded_and_challenge_gated() {
        let credential = GitBasicCredential::new("user".to_owned(), "token".to_owned()).unwrap();
        assert_eq!(
            basic_authorization(credential).unwrap().as_str(),
            "Basic dXNlcjp0b2tlbg=="
        );
        for (username, token) in [
            ("", "token"),
            ("user:name", "token"),
            ("user", ""),
            ("user", "line\nbreak"),
        ] {
            assert!(GitBasicCredential::new(username.to_owned(), token.to_owned()).is_err());
        }

        let mut headers = ureq::http::HeaderMap::new();
        headers.insert(
            "www-authenticate",
            ureq::http::HeaderValue::from_static("Basic realm=\"kitrove\""),
        );
        parse_basic_challenge(&headers).unwrap();
        for invalid in [
            "Bearer realm=\"kitrove\"",
            "Basic",
            "Basic realm=\"\"",
            "Basic realm=\"bad\\realm\"",
            "Basic realm=kitrove",
        ] {
            headers.insert(
                "www-authenticate",
                ureq::http::HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(parse_basic_challenge(&headers).is_err());
        }
        headers.insert(
            "www-authenticate",
            ureq::http::HeaderValue::from_static("Basic realm=\"kitrove\""),
        );
        headers.append(
            "www-authenticate",
            ureq::http::HeaderValue::from_static("Basic realm=\"other\""),
        );
        assert!(parse_basic_challenge(&headers).is_err());
    }

    #[test]
    fn packet_parser_refuses_truncation_invalid_lengths_and_record_overflow() {
        for invalid in [
            b"".as_slice(),
            b"000".as_slice(),
            b"0003".as_slice(),
            b"0008abc".as_slice(),
        ] {
            let mut remaining = SyncLimits::default().git().max_packet_lines();
            let mut cursor = PacketCursor::new(invalid, &mut remaining);
            if invalid.is_empty() {
                assert_eq!(cursor.next().unwrap(), None);
            } else {
                assert!(cursor.next().is_err());
            }
        }
        let mut remaining = 1;
        let mut cursor = PacketCursor::new(b"00000000", &mut remaining);
        assert_eq!(cursor.next().unwrap(), Some(PacketLine::Flush));
        assert!(cursor.next().is_err());
    }

    #[test]
    fn advertisement_selects_only_fixed_ref_after_charging_all_refs() {
        let oid = b"1111111111111111111111111111111111111111";
        let body = advertisement(&[
            &[
                oid.as_slice(),
                b" refs/heads/unrelated\0object-format=sha1 no-progress\n",
            ]
            .concat(),
            &[oid.as_slice(), b" refs/heads/kitrove-sync-v1\n"].concat(),
        ]);
        let parsed = parse_test_advertisement(&body, SyncLimits::default()).unwrap();
        assert_eq!(parsed.selected, Some(ObjectId::from_hex(oid).unwrap()));
        assert!(
            parsed
                .capabilities
                .contains(b"object-format=sha1".as_slice())
        );

        assert!(parse_test_advertisement(&body, tiny_git(body.len() as u64, 1, 8)).is_err());
        assert!(parse_test_advertisement(&body, tiny_git(body.len() as u64 - 1, 2, 8)).is_err());
    }

    #[test]
    fn ssh_advertisement_reuses_the_exact_ref_and_capability_parser() {
        let oid = b"1111111111111111111111111111111111111111";
        let body = ssh_advertisement(&[&[
            oid.as_slice(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress\n",
        ]
        .concat()]);
        let limits = SyncLimits::default();
        let mut budget = GitBudget::new(limits);
        let parsed = parse_ssh_advertisement(&body, limits, &mut budget).unwrap();
        assert_eq!(parsed.selected, Some(ObjectId::from_hex(oid).unwrap()));
        assert!(parsed.capabilities.contains(b"shallow".as_slice()));

        let http = advertisement(&[&[
            oid.as_slice(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1\n",
        ]
        .concat()]);
        let mut budget = GitBudget::new(limits);
        assert!(parse_ssh_advertisement(&http, limits, &mut budget).is_err());
    }

    #[test]
    fn advertisement_accepts_canonical_absence_and_refuses_non_sha1_or_peeled_refs() {
        let absent = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        ]);
        assert_eq!(
            parse_test_advertisement(&absent, SyncLimits::default())
                .unwrap()
                .selected,
            None
        );
        let sha256 = advertisement(&[
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha256\n",
        ]);
        assert!(parse_test_advertisement(&sha256, SyncLimits::default()).is_err());
        let peeled = advertisement(&[
            b"1111111111111111111111111111111111111111 refs/tags/v1^{}\0object-format=sha1\n",
        ]);
        assert!(parse_test_advertisement(&peeled, SyncLimits::default()).is_err());
        let symbolic = advertisement(&[
            b"1111111111111111111111111111111111111111 refs/heads/kitrove-sync-v1\0object-format=sha1 symref=HEAD:refs/heads/main\n",
        ]);
        assert_eq!(
            parse_test_advertisement(&symbolic, SyncLimits::default())
                .unwrap()
                .selected,
            Some(ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap())
        );
    }

    #[test]
    fn upload_request_is_exact_and_negotiates_only_bounded_capabilities() {
        let oid = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let capabilities = [
            b"shallow".to_vec(),
            b"no-progress".to_vec(),
            b"ofs-delta".to_vec(),
            b"side-band-64k".to_vec(),
        ]
        .into_iter()
        .collect();
        let request = build_upload_request(oid, &capabilities, SyncLimits::default()).unwrap();
        let mut expected =
            pkt(b"want 1111111111111111111111111111111111111111 shallow no-progress ofs-delta\n");
        expected.extend(pkt(format!(
            "deepen {}\n",
            SyncLimits::default().max_backend_history() + 1
        )
        .as_bytes()));
        expected.extend_from_slice(b"0000");
        expected.extend(pkt(b"done\n"));
        assert_eq!(request, expected);

        let missing = [b"shallow".to_vec()].into_iter().collect();
        let backend =
            GitSyncBackend::open("https://example.com/owner/repo.git", SyncLimits::default())
                .unwrap();
        let mut authentication = GitAuthentication::new(None);
        let deadline = GitOperationDeadline::new(SyncLimits::default()).unwrap();
        assert!(
            backend
                .fetch_selected(
                    oid,
                    &missing,
                    SyncLimits::default(),
                    &mut GitBudget::new(SyncLimits::default()),
                    &mut authentication,
                    &deadline,
                )
                .is_err()
        );
    }

    #[test]
    fn upload_response_extracts_only_canonical_positive_depth_pack() {
        let pack = test_pack(&[(ObjectKind::Blob, b"payload")]);
        let mut response = pkt(b"shallow 1111111111111111111111111111111111111111\n");
        response.extend_from_slice(b"0000");
        response.extend(pkt(b"NAK\n"));
        response.extend_from_slice(&pack);
        let limits = SyncLimits::default();
        let mut budget = GitBudget::new(limits);
        let extracted = extract_pack_response(&response, limits, &mut budget).unwrap();
        assert_eq!(extracted.pack, pack);
        assert_eq!(extracted.shallow.len(), 1);

        let mut bad_ack = b"0000".to_vec();
        bad_ack.extend(pkt(b"ACK\n"));
        bad_ack.extend_from_slice(&pack);
        let mut bad_shallow = pkt(b"shallow not-an-object-id\n");
        bad_shallow.extend_from_slice(b"0000");
        bad_shallow.extend(pkt(b"NAK\n"));
        bad_shallow.extend_from_slice(&pack);
        let mut bad_pack = b"0000".to_vec();
        bad_pack.extend(pkt(b"NAK\n"));
        bad_pack.extend_from_slice(b"NOPE");
        for malformed in [bad_ack, bad_shallow, bad_pack] {
            let mut budget = GitBudget::new(limits);
            assert!(extract_pack_response(&malformed, limits, &mut budget).is_err());
        }
    }

    #[test]
    fn pack_decoder_verifies_hashes_kinds_and_exact_boundaries() {
        let pack = test_pack(&[
            (ObjectKind::Blob, b"abc"),
            (ObjectKind::Tree, b""),
            (
                ObjectKind::Commit,
                b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\n",
            ),
        ]);
        let limits = pack_limits(pack.len() as u64, 3, 47, 50);
        let mut budget = GitBudget::new(limits);
        let objects = decode_pack(&pack, limits, &mut budget).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(
            objects
                .values()
                .any(|object| object.kind == ObjectKind::Commit)
        );
        assert_eq!(budget.remaining_decoded_objects, 0);
        assert_eq!(budget.remaining_decoded_bytes, 0);

        let mut corrupted = pack.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        let mut budget = GitBudget::new(limits);
        assert!(decode_pack(&corrupted, limits, &mut budget).is_err());

        for refusing in [
            pack_limits(pack.len() as u64 - 1, 3, 47, 50),
            pack_limits(pack.len() as u64, 2, 47, 50),
            pack_limits(pack.len() as u64, 3, 46, 50),
            pack_limits(pack.len() as u64, 3, 47, 49),
        ] {
            let mut budget = GitBudget::new(refusing);
            assert!(decode_pack(&pack, refusing, &mut budget).is_err());
        }

        let mut generated = GitObjectMap::new();
        insert_object(&mut generated, ObjectKind::Blob, b"abc");
        insert_object(&mut generated, ObjectKind::Tree, b"");
        insert_object(
            &mut generated,
            ObjectKind::Commit,
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\n",
        );
        let encoded = encode_pack(&generated, SyncLimits::default()).unwrap();
        assert_eq!(
            encoded,
            encode_pack(&generated, SyncLimits::default()).unwrap()
        );
        let mut budget = GitBudget::new(SyncLimits::default());
        let decoded = decode_pack(&encoded, SyncLimits::default(), &mut budget).unwrap();
        assert_eq!(decoded.len(), generated.len());
        for (oid, object) in generated {
            let actual = decoded.get(&oid).unwrap();
            assert_eq!(actual.kind, object.kind);
            assert_eq!(actual.data, object.data);
        }
    }

    #[test]
    fn pack_decoder_resolves_a_bounded_ofs_delta_without_disk_state() {
        // Generated once with Git's pack-objects using --delta-base-offset. This test
        // supplies only the complete pack bytes to the production decoder.
        let pack = fixture_bytes(
            "5041434b0000000200000002b58002789cedc1410900000804b0bf2d4f3081fdc11eb22d01000000beebecd401473c12006c25789c6b5568555820c09a975a51c20500199c03c941e8b1870e6fed8a98adbb17c9c0d43faf83d7db",
        );
        let limits = pack_limits(pack.len() as u64, 2, 4_101, 8_202);
        let mut budget = GitBudget::new(limits);
        let objects = decode_pack(&pack, limits, &mut budget).unwrap();
        assert_eq!(objects.len(), 2);
        assert!(
            objects
                .values()
                .all(|object| object.kind == ObjectKind::Blob)
        );
        assert!(
            objects
                .values()
                .any(|object| object.data.ends_with(b"base\n"))
        );
        assert!(
            objects
                .values()
                .any(|object| object.data.ends_with(b"next\n"))
        );
        assert_eq!(budget.remaining_decoded_objects, 0);
        assert_eq!(budget.remaining_decoded_bytes, 0);
    }

    #[test]
    fn pack_decoder_refuses_a_delta_chain_beyond_the_exact_depth_limit() {
        let pack = chained_delta_pack();
        let accepting = pack_shape_limits(pack.len() as u64, 3, 128, 128, 2);
        let mut budget = GitBudget::new(accepting);
        let objects = decode_pack(&pack, accepting, &mut budget).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(
            objects
                .values()
                .any(|object| object.data == b"grandchild payload\n")
        );

        let refusing = pack_shape_limits(pack.len() as u64, 3, 128, 128, 1);
        let mut budget = GitBudget::new(refusing);
        assert!(decode_pack(&pack, refusing, &mut budget).is_err());
    }

    #[test]
    fn pack_decoder_refuses_high_ratio_objects_before_decoded_allocation() {
        let expanded = vec![b'x'; 1024 * 1024];
        let pack = test_pack(&[(ObjectKind::Blob, expanded.as_slice())]);
        assert!(pack.len() < expanded.len() / 100);

        let limits = pack_limits(pack.len() as u64, 1, 64 * 1024, 64 * 1024);
        let mut budget = GitBudget::new(limits);
        assert!(decode_pack(&pack, limits, &mut budget).is_err());
        assert_eq!(budget.remaining_decoded_objects, 1);
        assert_eq!(budget.remaining_decoded_bytes, 64 * 1024);
    }

    #[test]
    fn pack_decoder_refuses_tag_objects() {
        let pack = test_pack(&[(
            ObjectKind::Tag,
            b"object 1111111111111111111111111111111111111111\n",
        )]);
        let limits = SyncLimits::default();
        let mut budget = GitBudget::new(limits);
        assert!(decode_pack(&pack, limits, &mut budget).is_err());
    }

    #[test]
    fn selected_commit_tree_reconstructs_and_verifies_exact_snapshot_objects() {
        let limits = SyncLimits::default();
        let payload_path = PortablePath::parse("SKILL.md").unwrap();
        let payload_files = BTreeMap::from([(
            payload_path,
            CapturedFile {
                mode: FileMode::Executable,
                bytes: b"portable payload\n".to_vec(),
            },
        )]);
        let portable = StoredSkillTree::new(CapturedTree {
            hash: hash_tree(&payload_files),
            files: payload_files,
        })
        .unwrap();
        let envelope = VerifiedObjectEnvelope::portable(
            PortablePath::parse("assets/review/portable").unwrap(),
            portable.clone(),
        )
        .unwrap();
        let mut manifest = portable_manifest();
        let asset = manifest.assets.values_mut().next().unwrap();
        asset.portable.as_mut().unwrap().object_hash = envelope.descriptor().object_hash().clone();
        asset.refresh_content_hash();
        manifest.refresh_pack_revisions().unwrap();
        let snapshot = PortableSnapshotV1::new(
            manifest,
            BTreeSet::from([envelope.descriptor().clone()]),
            limits,
        )
        .unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            std::slice::from_ref(&envelope),
            limits,
        )
        .unwrap();
        let persisted: GitPublicationIntentV1 =
            serde_json::from_str(intent.as_persisted()).unwrap();
        assert_eq!(persisted.schema_version, 1);
        assert!(persisted.object_oids.len() > 3);
        assert_eq!(
            intent.proposed_revision().as_str(),
            format!("git:sha1:{}", persisted.commit_oid)
        );
        let snapshot_json = snapshot.to_json(limits).unwrap();
        let metadata_json = portable.metadata_json();
        let mut source = TestTree::default();
        source.insert("snapshot.json", snapshot_json.as_bytes());
        source.insert(
            "objects/assets/review/portable/metadata.json",
            metadata_json.as_bytes(),
        );
        source.insert(
            "objects/assets/review/portable/payload/SKILL.md",
            b"portable payload\n",
        );
        let mut objects = GitObjectMap::new();
        let tree = source.store(&mut objects);
        let selected = commit(&mut objects, tree, &[]);
        let verified = verify_selected_snapshot(
            selected,
            &FetchedGit {
                objects: objects.clone(),
                shallow: BTreeSet::new(),
            },
            limits,
        )
        .unwrap();
        assert_eq!(verified.snapshot, snapshot);
        assert_eq!(verified.objects.len(), 1);
        assert_eq!(verified.history, vec![selected]);

        let empty_manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let current = PortableSnapshotV1::new(empty_manifest, BTreeSet::new(), limits).unwrap();
        let mut current_tree = TestTree::default();
        current_tree.insert("snapshot.json", current.to_json(limits).unwrap().as_bytes());
        let current_tree = current_tree.store(&mut objects);
        let current_commit = commit(&mut objects, current_tree, &[selected]);
        let history = verify_selected_history(
            current_commit,
            &FetchedGit {
                objects,
                shallow: BTreeSet::new(),
            },
            limits,
        )
        .unwrap();
        assert_eq!(history.snapshots.len(), 2);
        assert_eq!(
            history.objects.get(envelope.descriptor().root()),
            Some(&envelope)
        );
    }

    #[test]
    fn selected_git_history_verifies_every_snapshot_newest_first() {
        let limits = SyncLimits::default();
        let older_manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let older =
            PortableSnapshotV1::new(older_manifest.clone(), BTreeSet::new(), limits).unwrap();
        let mut current_manifest = older_manifest;
        let profile_id = kitrove_model::ProfileId::parse("workstation").unwrap();
        current_manifest.profiles.insert(
            profile_id.clone(),
            kitrove_model::Profile {
                id: profile_id,
                extends: None,
                assets: BTreeSet::new(),
                targets: BTreeSet::new(),
            },
        );
        let current = PortableSnapshotV1::new(current_manifest, BTreeSet::new(), limits).unwrap();
        let mut objects = GitObjectMap::new();
        let mut older_tree = TestTree::default();
        older_tree.insert("snapshot.json", older.to_json(limits).unwrap().as_bytes());
        let older_tree = older_tree.store(&mut objects);
        let older_commit = commit(&mut objects, older_tree, &[]);
        let mut current_tree = TestTree::default();
        current_tree.insert("snapshot.json", current.to_json(limits).unwrap().as_bytes());
        let current_tree = current_tree.store(&mut objects);
        let current_commit = commit(&mut objects, current_tree, &[older_commit]);
        let repeated_commit = commit(&mut objects, current_tree, &[current_commit]);
        let fetched = FetchedGit {
            objects: objects.clone(),
            shallow: BTreeSet::new(),
        };

        let verified = verify_selected_history(repeated_commit, &fetched, limits).unwrap();

        assert_eq!(
            verified.commits,
            vec![repeated_commit, current_commit, older_commit]
        );
        assert_eq!(verified.snapshots[0].1.as_ref(), &current);
        assert!(Arc::ptr_eq(
            &verified.snapshots[0].1,
            &verified.snapshots[1].1
        ));
        assert_eq!(verified.snapshots[2].1.as_ref(), &older);
        let snapshot_bytes = (current.to_json(limits).unwrap().len()
            + older.to_json(limits).unwrap().len()
            - 1) as u64;
        let constrained = SyncLimits::new(
            snapshot_bytes,
            limits.max_control_bytes(),
            current
                .manifest_toml()
                .len()
                .max(older.manifest_toml().len()) as u64,
            current.lock_json().len().max(older.lock_json().len()) as u64,
            limits.max_object_count(),
            limits.max_object_bytes(),
            limits.max_total_object_bytes(),
            limits.max_conflicts(),
            limits.max_components(),
            3,
        )
        .unwrap();
        assert_eq!(
            verify_selected_history(repeated_commit, &fetched, constrained)
                .err()
                .unwrap()
                .code(),
            "sync_backend.git_limit_exceeded"
        );
        let mut session = GitReadSession {
            observed: finish_git_observation(Some(repeated_commit), Some(fetched), limits).unwrap(),
        };
        let observed_history = session.inspect_history(limits).unwrap();
        assert_eq!(observed_history.snapshots().len(), 3);
        assert_eq!(
            observed_history.snapshots()[0].revision().as_str(),
            format!("git:sha1:{repeated_commit}")
        );

        let mut invalid_objects = objects;
        let mut invalid_older_tree = TestTree::default();
        invalid_older_tree.insert(
            "snapshot.json",
            verified.snapshots[2].1.to_json(limits).unwrap().as_bytes(),
        );
        invalid_older_tree.insert("extra", b"unauthorized");
        let invalid_older_tree = invalid_older_tree.store(&mut invalid_objects);
        let invalid_older_commit = commit(&mut invalid_objects, invalid_older_tree, &[]);
        let invalid_current_commit =
            commit(&mut invalid_objects, current_tree, &[invalid_older_commit]);
        assert!(
            verify_selected_history(
                invalid_current_commit,
                &FetchedGit {
                    objects: invalid_objects,
                    shallow: BTreeSet::new(),
                },
                limits,
            )
            .is_err()
        );
    }

    #[test]
    fn selected_commit_tree_reconstructs_exact_native_extension_objects() {
        let limits = SyncLimits::default();
        let adoption = crate::native_extension_adoption::tests::ready_plan();
        let native = &adoption.asset().native_variants[&kitrove_model::HarnessId::Pi];
        let envelope = VerifiedObjectEnvelope::native_extension(
            native.root.clone(),
            adoption.native_object().clone(),
        )
        .unwrap();
        let snapshot = PortableSnapshotV1::new(
            adoption.proposed_manifest().clone(),
            BTreeSet::from([envelope.descriptor().clone()]),
            limits,
        )
        .unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap();
        prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            std::slice::from_ref(&envelope),
            limits,
        )
        .unwrap();

        let mut source = TestTree::default();
        source.insert(
            "snapshot.json",
            snapshot.to_json(limits).unwrap().as_bytes(),
        );
        source.insert(
            &format!("objects/{}/metadata.json", native.root.as_str()),
            adoption.native_object().metadata_json().as_bytes(),
        );
        for (path, file) in &adoption.native_object().tree().files {
            source.insert(
                &format!("objects/{}/payload/{}", native.root.as_str(), path.as_str()),
                &file.bytes,
            );
        }
        let mut objects = GitObjectMap::new();
        let tree = source.store(&mut objects);
        let selected = commit(&mut objects, tree, &[]);
        let verified = verify_selected_snapshot(
            selected,
            &FetchedGit {
                objects,
                shallow: BTreeSet::new(),
            },
            limits,
        )
        .unwrap();
        assert_eq!(verified.snapshot, snapshot);
        assert_eq!(
            verified.objects.get(envelope.descriptor().root()),
            Some(&envelope)
        );
        assert_eq!(verified.objects.len(), 1);
    }

    #[test]
    fn git_reconstructed_objects_refuse_case_and_unicode_path_aliases() {
        let limits = SyncLimits::default();
        let payload_files = BTreeMap::from([(
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"portable payload\n".to_vec(),
            },
        )]);
        let portable = StoredSkillTree::new(CapturedTree {
            hash: hash_tree(&payload_files),
            files: payload_files,
        })
        .unwrap();
        let envelope = VerifiedObjectEnvelope::portable(
            PortablePath::parse("assets/review/portable").unwrap(),
            portable,
        )
        .unwrap();
        let mut manifest = portable_manifest();
        let asset = manifest.assets.values_mut().next().unwrap();
        asset.portable.as_mut().unwrap().object_hash = envelope.descriptor().object_hash().clone();
        asset.refresh_content_hash();
        manifest.refresh_pack_revisions().unwrap();
        let snapshot = PortableSnapshotV1::new(
            manifest,
            BTreeSet::from([envelope.descriptor().clone()]),
            limits,
        )
        .unwrap()
        .to_json(limits)
        .unwrap();

        for aliases in [
            ["README.md", "Readme.md"],
            ["caf\u{e9}.md", "cafe\u{301}.md"],
        ] {
            let file_modes = BTreeMap::from([(aliases[0], "regular"), (aliases[1], "regular")]);
            let metadata = serde_json::to_string(&serde_json::json!({
                "schema_version": 1,
                "files": file_modes,
            }))
            .unwrap();
            let mut source = TestTree::default();
            source.insert("snapshot.json", snapshot.as_bytes());
            source.insert(
                "objects/assets/review/portable/metadata.json",
                metadata.as_bytes(),
            );
            for alias in aliases {
                source.insert(
                    &format!("objects/assets/review/portable/payload/{alias}"),
                    b"alias payload\n",
                );
            }
            let mut objects = GitObjectMap::new();
            let tree = source.store(&mut objects);
            let selected = commit(&mut objects, tree, &[]);
            assert!(
                verify_selected_snapshot(
                    selected,
                    &FetchedGit {
                        objects,
                        shallow: BTreeSet::new(),
                    },
                    limits,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn publication_intent_is_deterministic_and_binds_parent_publication_and_snapshot() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let expected = RemoteRevision::parse(format!("git:sha1:{}", "1".repeat(40))).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let first =
            prepare_git_publication(&expected, &publication, &snapshot, &[], limits).unwrap();
        let second =
            prepare_git_publication(&expected, &publication, &snapshot, &[], limits).unwrap();
        assert_eq!(first, second);
        let parsed: GitPublicationIntentV1 = serde_json::from_str(first.as_persisted()).unwrap();
        assert_eq!(parsed.expected, expected);
        assert_eq!(parsed.publication_id, publication);
        assert_eq!(parsed.snapshot_digest, *snapshot.snapshot_digest());
        assert!(parsed.object_oids.contains(&parsed.tree_oid));
        assert!(parsed.object_oids.contains(&parsed.commit_oid));

        let different =
            PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap();
        let changed =
            prepare_git_publication(&expected, &different, &snapshot, &[], limits).unwrap();
        assert_ne!(first.proposed_revision(), changed.proposed_revision());
        assert!(
            prepare_git_publication(
                &RemoteRevision::parse("filesystem:absent:v1").unwrap(),
                &publication,
                &snapshot,
                &[],
                limits,
            )
            .is_err()
        );
    }

    #[test]
    fn receive_request_is_exact_and_status_requires_one_complete_acknowledgement() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let expected = RemoteRevision::parse(format!("git:sha1:{}", "1".repeat(40))).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let constructed =
            construct_git_publication(&expected, &publication, &snapshot, &[], limits).unwrap();
        let request = build_receive_request(
            constructed.expected_oid,
            constructed.commit_oid,
            &constructed.pack,
            limits,
        )
        .unwrap();
        let mut remaining = limits.git().max_packet_lines();
        let mut cursor = PacketCursor::new(&request, &mut remaining);
        let expected_command = format!(
            "{} {} refs/heads/kitrove-sync-v1\0report-status\n",
            constructed.expected_oid, constructed.commit_oid
        );
        assert_eq!(
            cursor.next().unwrap(),
            Some(PacketLine::Data(expected_command.as_bytes()))
        );
        assert_eq!(cursor.next().unwrap(), Some(PacketLine::Flush));
        assert_eq!(&request[cursor.offset..], constructed.pack);

        let mut status = pkt(b"unpack ok\n");
        status.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        status.extend_from_slice(b"0000");
        let mut budget = GitBudget::new(limits);
        parse_receive_status(&status, &mut budget).unwrap();
        for invalid in [
            pkt(b"unpack failed\n"),
            [
                pkt(b"unpack ok\n"),
                pkt(b"ng refs/heads/kitrove-sync-v1 rejected\n"),
            ]
            .concat(),
            [
                pkt(b"unpack ok\n"),
                pkt(b"ok refs/heads/other\n"),
                b"0000".to_vec(),
            ]
            .concat(),
            [status.clone(), pkt(b"ok refs/heads/kitrove-sync-v1\n")].concat(),
        ] {
            let mut budget = GitBudget::new(limits);
            assert!(parse_receive_status(&invalid, &mut budget).is_err());
        }
    }

    #[test]
    fn publication_intent_parser_refuses_extension_and_noncanonical_encoding() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        assert!(parse_publication_intent(&intent, limits).is_ok());

        let extended = intent
            .as_persisted()
            .replacen("{\n", "{\n  \"extension\": true,\n", 1);
        let forged =
            PublicationIntent::from_persisted(extended, intent.proposed_revision().clone(), limits)
                .unwrap();
        assert!(parse_publication_intent(&forged, limits).is_err());

        let compact: serde_json::Value = serde_json::from_str(intent.as_persisted()).unwrap();
        let compact = serde_json::to_string(&compact).unwrap();
        let forged =
            PublicationIntent::from_persisted(compact, intent.proposed_revision().clone(), limits)
                .unwrap();
        assert!(parse_publication_intent(&forged, limits).is_err());
    }

    #[test]
    fn reconciliation_requires_selected_history_or_the_exact_expected_revision() {
        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let intent = prepare_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let parsed = parse_publication_intent(&intent, limits).unwrap();
        let proposed = ObjectId::from_hex(parsed.commit_oid.as_bytes()).unwrap();

        let ready = GitObservation {
            remote: RemoteSnapshot::absent(parsed.expected.clone()),
            objects: BTreeMap::new(),
            history: Vec::new(),
            rollback_history: None,
        };
        assert_eq!(
            reconcile_git_observation(&intent, &parsed, proposed, &ready),
            PublicationStatus::Ready
        );

        let competing = RemoteRevision::parse(format!("git:sha1:{}", "2".repeat(40))).unwrap();
        let published = GitObservation {
            remote: RemoteSnapshot::absent(competing.clone()),
            objects: BTreeMap::new(),
            history: vec![proposed],
            rollback_history: None,
        };
        assert_eq!(
            reconcile_git_observation(&intent, &parsed, proposed, &published),
            PublicationStatus::Published(intent.proposed_revision().clone())
        );

        let uncertain = GitObservation {
            remote: RemoteSnapshot::absent(competing),
            objects: BTreeMap::new(),
            history: Vec::new(),
            rollback_history: None,
        };
        assert_eq!(
            reconcile_git_observation(&intent, &parsed, proposed, &uncertain),
            PublicationStatus::Uncertain
        );
    }

    #[test]
    fn integrated_https_reconciliation_proves_successors_and_refuses_alternate_or_broken_history() {
        fn reconcile_over_https(
            intent: &PublicationIntent,
            selected: ObjectId,
            objects: &GitObjectMap,
            limits: SyncLimits,
        ) -> PublicationStatus {
            let selected_oid = selected.to_string();
            let selected_record = [
                selected_oid.as_bytes(),
                b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
            ]
            .concat();
            let selected_upload = advertisement(&[&selected_record]);
            let mut upload_response = b"0000".to_vec();
            upload_response.extend(pkt(b"NAK\n"));
            upload_response.extend_from_slice(&encode_pack(objects, limits).unwrap());
            let (address, root, requests, server) = spawn_https_fixture(vec![
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![(
                        "Content-Type",
                        "application/x-git-upload-pack-advertisement",
                    )],
                    body: selected_upload,
                },
                FixtureResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "application/x-git-upload-pack-result")],
                    body: upload_response,
                },
            ]);
            let backend = GitSyncBackend::open_for_test(
                "https://fixture.invalid/owner/repo.git",
                limits,
                root,
                address,
                None,
            )
            .unwrap();
            let mut session = GitApplySession {
                backend: &backend,
                observed: GitObservation {
                    remote: RemoteSnapshot::absent(RemoteRevision::parse("git:absent:v1").unwrap()),
                    objects: BTreeMap::new(),
                    history: Vec::new(),
                    rollback_history: None,
                },
            };
            let status = session.reconcile(intent, limits).unwrap();
            let _ = requests.recv().unwrap();
            let _ = requests.recv().unwrap();
            server.join().unwrap();
            status
        }

        let limits = SyncLimits::default();
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let constructed = construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let parsed = parse_publication_intent(&constructed.intent, limits).unwrap();
        let tree = ObjectId::from_hex(parsed.tree_oid.as_bytes()).unwrap();
        let mut budget = GitBudget::new(limits);
        let mut objects = decode_pack(&constructed.pack, limits, &mut budget).unwrap();
        let successor = commit(&mut objects, tree, &[constructed.commit_oid]);
        assert_eq!(
            reconcile_over_https(&constructed.intent, successor, &objects, limits),
            PublicationStatus::Published(constructed.intent.proposed_revision().clone())
        );

        let later_successor = commit(&mut objects, tree, &[successor]);
        assert_eq!(
            reconcile_over_https(&constructed.intent, later_successor, &objects, limits),
            PublicationStatus::Published(constructed.intent.proposed_revision().clone())
        );

        let alternate_data = format!(
            "tree {tree}\nauthor KitRove <kitrove@invalid> 0 +0000\ncommitter KitRove <kitrove@invalid> 0 +0000\n\nalternate-history\n"
        );
        let alternate = insert_object(&mut objects, ObjectKind::Commit, alternate_data.as_bytes());
        assert_eq!(
            reconcile_over_https(&constructed.intent, alternate, &objects, limits),
            PublicationStatus::Uncertain
        );

        let missing = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let broken = commit(&mut objects, tree, &[missing]);
        assert_eq!(
            reconcile_over_https(&constructed.intent, broken, &objects, limits),
            PublicationStatus::Uncertain
        );
    }

    #[test]
    fn selected_history_and_tree_refuse_missing_ancestry_extra_files_and_forbidden_modes() {
        let limits = SyncLimits::default();
        let empty_manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let snapshot = PortableSnapshotV1::new(empty_manifest, BTreeSet::new(), limits)
            .unwrap()
            .to_json(limits)
            .unwrap();
        let mut source = TestTree::default();
        source.insert("snapshot.json", snapshot.as_bytes());
        source.insert("extra", b"not authorized");
        let mut objects = GitObjectMap::new();
        let tree = source.store(&mut objects);
        let missing_parent =
            ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let selected = commit(&mut objects, tree, &[missing_parent]);
        assert!(
            verify_selected_snapshot(
                selected,
                &FetchedGit {
                    objects: objects.clone(),
                    shallow: BTreeSet::new(),
                },
                limits,
            )
            .is_err()
        );

        let shallow = BTreeSet::from([selected]);
        assert!(
            verify_selected_snapshot(
                selected,
                &FetchedGit {
                    objects: objects.clone(),
                    shallow,
                },
                limits,
            )
            .is_err()
        );

        let root = objects.get(&tree).unwrap();
        let mut forbidden = root.data.clone();
        forbidden[..6].copy_from_slice(b"100755");
        let forbidden_tree = insert_object(&mut objects, ObjectKind::Tree, &forbidden);
        let forbidden_commit = commit(&mut objects, forbidden_tree, &[]);
        assert!(
            verify_selected_snapshot(
                forbidden_commit,
                &FetchedGit {
                    objects: objects.clone(),
                    shallow: BTreeSet::new(),
                },
                limits,
            )
            .is_err()
        );

        let parent = commit(&mut objects, tree, &[]);
        let child = commit(&mut objects, tree, &[parent]);
        assert!(
            verify_commit_chain(
                child,
                &FetchedGit {
                    objects,
                    shallow: BTreeSet::new(),
                },
                history_limits(1),
            )
            .is_err()
        );
    }
}
