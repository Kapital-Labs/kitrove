use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::path::{Path, PathBuf};

use gix_hash::{Kind as HashKind, ObjectId};
use kitrove_model::{ObjectDescriptor, PublicationId, RemoteKey, RemoteRevision, SyncLimits};

use super::{
    ConstructedPublication, FetchedGit, GitBudget, GitObservation, build_receive_request,
    build_upload_request, decode_pack, extract_pack_response, fetch_observed_object,
    finish_git_observation, intent_invalid, invalid_protocol, limit_exceeded,
    parse_publication_intent, parse_receive_status, parse_ssh_advertisement,
    prepare_git_publication, reconcile_git_observation, require_upload_capabilities, stale,
    validate_git_publication,
};
use crate::git_remote::{GitSshService, SshGitRemoteUrl};
use crate::ssh_git_transport::open_ssh_service;
#[cfg(all(test, unix))]
use crate::ssh_git_transport::open_ssh_service_with_agent_socket;
use crate::sync_backend::sealed::Sealed;
use crate::{
    BackendError, PortableSnapshotV1, PublicationIntent, PublicationStatus, RemoteSnapshot,
    SyncBackend, SyncBackendApply, SyncBackendRead, VerifiedObjectEnvelope, VerifiedRemoteHistory,
};

/// A bounded smart-Git SSH backend using only verified known-host and agent authority.
pub struct SshGitSyncBackend {
    remote: SshGitRemoteUrl,
    known_hosts: PathBuf,
    #[cfg(all(test, unix))]
    agent_socket: Option<PathBuf>,
}

impl SshGitSyncBackend {
    /// Opens one canonical SSH remote without performing network or filesystem I/O.
    pub fn open(remote: &str, known_hosts: impl AsRef<Path>) -> Result<Self, BackendError> {
        let remote = SshGitRemoteUrl::parse(remote)?;
        let known_hosts = known_hosts.as_ref();
        if !known_hosts.is_absolute() {
            return Err(ssh_configuration_invalid());
        }
        Ok(Self {
            remote,
            known_hosts: known_hosts.to_owned(),
            #[cfg(all(test, unix))]
            agent_socket: None,
        })
    }

    #[cfg(all(test, unix))]
    fn open_for_test(
        remote: &str,
        known_hosts: impl AsRef<Path>,
        agent_socket: impl AsRef<Path>,
    ) -> Result<Self, BackendError> {
        let mut backend = Self::open(remote, known_hosts)?;
        backend.agent_socket = Some(agent_socket.as_ref().to_owned());
        Ok(backend)
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
        run_ssh_operation(self.inspect_observation_async(limits))
    }

    async fn inspect_observation_async(
        &self,
        limits: SyncLimits,
    ) -> Result<GitObservation, BackendError> {
        let mut budget = GitBudget::new(limits);
        let mut session = self.open_service(GitSshService::UploadPack, limits).await?;
        let body = session.read_advertisement(limits).await?;
        budget.charge_response(body.len() as u64)?;
        let advertisement = parse_ssh_advertisement(&body, limits, &mut budget)?;
        let fetched = match advertisement.selected {
            Some(selected) => {
                require_upload_capabilities(&advertisement.capabilities)?;
                let request = build_upload_request(selected, &advertisement.capabilities, limits)?;
                let response_limit = limits
                    .git()
                    .max_received_pack_bytes()
                    .checked_add(limits.git().max_advertisement_bytes())
                    .ok_or_else(limit_exceeded)?;
                let response = session.exchange(request, response_limit, limits).await?;
                budget.charge_response(response.len() as u64)?;
                let response = extract_pack_response(&response, limits, &mut budget)?;
                let objects = decode_pack(response.pack, limits, &mut budget)?;
                Some(FetchedGit {
                    objects,
                    shallow: response.shallow,
                })
            }
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
        let constructed = validate_git_publication(intent, staged, objects, limits)?;
        run_ssh_operation(self.publish_async(intent, constructed, limits))
    }

    async fn publish_async(
        &self,
        intent: &PublicationIntent,
        constructed: ConstructedPublication,
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        let mut budget = GitBudget::new(limits);
        let mut session = self
            .open_service(GitSshService::ReceivePack, limits)
            .await?;
        let body = session.read_advertisement(limits).await?;
        budget.charge_response(body.len() as u64)?;
        let advertisement = parse_ssh_advertisement(&body, limits, &mut budget)?;
        if !advertisement
            .capabilities
            .contains(b"report-status".as_slice())
        {
            return Err(invalid_protocol());
        }
        let advertised = advertisement
            .selected
            .unwrap_or_else(|| ObjectId::null(HashKind::Sha1));
        if advertised != constructed.expected_oid {
            return Ok(PublicationStatus::Uncertain);
        }
        let request = build_receive_request(
            constructed.expected_oid,
            constructed.commit_oid,
            &constructed.pack,
            limits,
        )?;
        let response = match session
            .exchange(request, limits.git().max_advertisement_bytes(), limits)
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(PublicationStatus::Uncertain),
        };
        if budget.charge_response(response.len() as u64).is_err()
            || parse_receive_status(&response, &mut budget).is_err()
        {
            return Ok(PublicationStatus::Uncertain);
        }
        Ok(PublicationStatus::Published(
            intent.proposed_revision().clone(),
        ))
    }

    async fn open_service(
        &self,
        service: GitSshService,
        limits: SyncLimits,
    ) -> Result<crate::ssh_git_transport::SshServiceSession, BackendError> {
        #[cfg(all(test, unix))]
        if let Some(agent_socket) = &self.agent_socket {
            return open_ssh_service_with_agent_socket(
                &self.remote,
                &self.known_hosts,
                agent_socket,
                service,
                limits,
            )
            .await;
        }
        open_ssh_service(&self.remote, &self.known_hosts, service, limits).await
    }
}

fn run_ssh_operation<T>(
    operation: impl Future<Output = Result<T, BackendError>>,
) -> Result<T, BackendError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(ssh_runtime_failed());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| ssh_runtime_failed())?;
    runtime.block_on(operation)
}

impl Debug for SshGitSyncBackend {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshGitSyncBackend")
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl Sealed for SshGitSyncBackend {}

impl SyncBackend for SshGitSyncBackend {
    type ReadSession<'a> = SshGitReadSession;
    type ApplySession<'a> = SshGitApplySession<'a>;

    fn inspect(&self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        SshGitSyncBackend::inspect(self, limits)
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
        Ok(SshGitReadSession {
            observed: self.inspect_observation(limits)?,
        })
    }

    fn begin_apply(&self, limits: SyncLimits) -> Result<Self::ApplySession<'_>, BackendError> {
        Ok(SshGitApplySession {
            backend: self,
            observed: self.inspect_observation(limits)?,
        })
    }
}

/// One immutable, fully verified Git-over-SSH read observation.
pub struct SshGitReadSession {
    observed: GitObservation,
}

impl SyncBackendRead for SshGitReadSession {
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
            .ok_or_else(super::invalid_history)
    }

    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        _limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_observed_object(&self.observed, descriptor)
    }
}

/// One Git-over-SSH apply session using the exact-old receive command as its CAS boundary.
pub struct SshGitApplySession<'a> {
    backend: &'a SshGitSyncBackend,
    observed: GitObservation,
}

impl SyncBackendApply for SshGitApplySession<'_> {
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
        self.backend.publish(intent, staged, objects, limits)
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

const fn ssh_configuration_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_configuration_invalid",
        "SSH transport configuration is invalid",
    )
}

const fn ssh_runtime_failed() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_runtime_failed",
        "SSH transport runtime failed",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use russh::server::Server as _;
    #[cfg(unix)]
    use std::collections::{BTreeSet, VecDeque};
    #[cfg(unix)]
    use std::sync::{Arc, Mutex};

    use super::*;

    #[cfg(unix)]
    struct SshExchangeScript {
        command: &'static [u8],
        advertisement: Vec<u8>,
        response: Option<Vec<u8>>,
    }

    #[cfg(unix)]
    #[derive(Clone)]
    struct ScriptedSshServer {
        scripts: Arc<Mutex<VecDeque<SshExchangeScript>>>,
    }

    #[cfg(unix)]
    struct ScriptedSshHandler {
        scripts: Arc<Mutex<VecDeque<SshExchangeScript>>>,
        response: Option<Vec<u8>>,
    }

    #[cfg(unix)]
    impl russh::server::Server for ScriptedSshServer {
        type Handler = ScriptedSshHandler;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            ScriptedSshHandler {
                scripts: Arc::clone(&self.scripts),
                response: None,
            }
        }
    }

    #[cfg(unix)]
    impl russh::server::Handler for ScriptedSshHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &russh::keys::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            command: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let script = self
                .scripts
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected SSH service session");
            assert_eq!(command, script.command);
            self.response = script.response;
            session.channel_success(channel)?;
            session.data(channel, script.advertisement)?;
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if let Some(response) = self.response.take() {
                session.data(channel, response)?;
            }
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
            Ok(())
        }
    }

    #[cfg(unix)]
    struct RunningSshServer {
        port: u16,
        handle: russh::server::RunningServerHandle,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl Drop for RunningSshServer {
        fn drop(&mut self) {
            self.handle.shutdown("test complete".to_owned());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn start_ssh_server(
        mut server: ScriptedSshServer,
        host_key: russh::keys::PrivateKey,
    ) -> RunningSshServer {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            ..<_>::default()
        });
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let running = server.run_on_socket(config, &listener);
                sender.send(running.handle()).unwrap();
                running.await.unwrap();
            });
        });
        RunningSshServer {
            port,
            handle: receiver.recv().unwrap(),
            thread: Some(thread),
        }
    }

    #[cfg(unix)]
    struct AgentIncoming {
        listener: tokio::net::UnixListener,
    }

    #[cfg(unix)]
    impl futures::Stream for AgentIncoming {
        type Item = std::io::Result<tokio::net::UnixStream>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.listener.poll_accept(context) {
                std::task::Poll::Ready(Ok((stream, _))) => std::task::Poll::Ready(Some(Ok(stream))),
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Some(Err(error))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    #[cfg(unix)]
    struct RunningAgentServer {
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl Drop for RunningAgentServer {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn start_agent_server(socket: &Path, identity: &russh::keys::PrivateKey) -> RunningAgentServer {
        let socket = socket.to_owned();
        let server_socket = socket.clone();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::bind(server_socket).unwrap();
                ready_sender.send(()).unwrap();
                tokio::select! {
                    result = russh::keys::agent::server::serve(AgentIncoming { listener }, ()) => {
                        result.unwrap();
                    }
                    _ = shutdown_receiver => {}
                }
            });
        });
        ready_receiver.recv().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        runtime.block_on(async {
            let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
            let mut agent = russh::keys::agent::client::AgentClient::connect(stream);
            agent.add_identity(identity, &[]).await.unwrap();
        });
        RunningAgentServer {
            shutdown: Some(shutdown_sender),
            thread: Some(thread),
        }
    }

    #[cfg(unix)]
    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
        packet.extend_from_slice(payload);
        packet
    }

    #[cfg(unix)]
    fn test_private_key() -> russh::keys::PrivateKey {
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap()
    }

    #[cfg(unix)]
    fn advertisement(record: &[u8]) -> Vec<u8> {
        let mut value = pkt(record);
        value.extend_from_slice(b"0000");
        value
    }

    #[cfg(unix)]
    const UPLOAD_COMMAND: &[u8] = b"git-upload-pack '/owner/repo.git'";
    #[cfg(unix)]
    const RECEIVE_COMMAND: &[u8] = b"git-receive-pack '/owner/repo.git'";

    #[cfg(unix)]
    fn empty_snapshot(limits: SyncLimits) -> PortableSnapshotV1 {
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap()
    }

    #[cfg(unix)]
    struct SshFixture {
        backend: SshGitSyncBackend,
        scripts: Arc<Mutex<VecDeque<SshExchangeScript>>>,
        _ssh_server: RunningSshServer,
        _agent_server: RunningAgentServer,
        _temporary: tempfile::TempDir,
    }

    #[cfg(unix)]
    fn ssh_contract_fixture() -> SshFixture {
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot(limits);
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "a".repeat(64))).unwrap();
        let constructed = crate::git_sync_backend::construct_git_publication(
            &RemoteRevision::parse("git:absent:v1").unwrap(),
            &publication,
            &snapshot,
            &[],
            limits,
        )
        .unwrap();
        let absent_upload = advertisement(
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1\n",
        );
        let absent_receive = advertisement(
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
        );
        let selected_record = [
            constructed.commit_oid.to_string().as_bytes(),
            b" refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        ]
        .concat();
        let selected_upload = advertisement(&selected_record);
        let mut upload_response = b"0000".to_vec();
        upload_response.extend(pkt(b"NAK\n"));
        upload_response.extend_from_slice(&constructed.pack);
        let mut receive_response = pkt(b"unpack ok\n");
        receive_response.extend(pkt(b"ok refs/heads/kitrove-sync-v1\n"));
        receive_response.extend_from_slice(b"0000");
        start_ssh_fixture(VecDeque::from([
            SshExchangeScript {
                command: UPLOAD_COMMAND,
                advertisement: absent_upload.clone(),
                response: None,
            },
            SshExchangeScript {
                command: UPLOAD_COMMAND,
                advertisement: absent_upload,
                response: None,
            },
            SshExchangeScript {
                command: RECEIVE_COMMAND,
                advertisement: absent_receive,
                response: Some(receive_response),
            },
            SshExchangeScript {
                command: UPLOAD_COMMAND,
                advertisement: selected_upload.clone(),
                response: Some(upload_response.clone()),
            },
            SshExchangeScript {
                command: UPLOAD_COMMAND,
                advertisement: selected_upload.clone(),
                response: Some(upload_response.clone()),
            },
            SshExchangeScript {
                command: UPLOAD_COMMAND,
                advertisement: selected_upload,
                response: Some(upload_response),
            },
        ]))
    }

    #[cfg(unix)]
    fn start_ssh_fixture(scripts: VecDeque<SshExchangeScript>) -> SshFixture {
        let scripts = Arc::new(Mutex::new(scripts));
        let host_key = test_private_key();
        let authority = host_key.public_key().to_openssh().unwrap();
        let ssh_server = start_ssh_server(
            ScriptedSshServer {
                scripts: Arc::clone(&scripts),
            },
            host_key,
        );
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let known_hosts = root.join("known_hosts");
        let agent_socket = root.join("agent.sock");
        std::fs::write(
            &known_hosts,
            format!("[localhost]:{} {authority}\n", ssh_server.port),
        )
        .unwrap();
        let identity = test_private_key();
        let agent_server = start_agent_server(&agent_socket, &identity);
        let backend = SshGitSyncBackend::open_for_test(
            &format!("ssh://git@localhost:{}/owner/repo.git", ssh_server.port),
            &known_hosts,
            &agent_socket,
        )
        .unwrap();
        SshFixture {
            backend,
            scripts,
            _ssh_server: ssh_server,
            _agent_server: agent_server,
            _temporary: temporary,
        }
    }

    #[test]
    fn open_is_network_free_and_debug_is_redacted() {
        let known_hosts = std::env::temp_dir().join("kitrove-known-hosts-canary");
        let backend =
            SshGitSyncBackend::open("ssh://git@example.com/owner/repo.git", &known_hosts).unwrap();
        let rendered = format!("{backend:?}");
        assert!(!rendered.contains("example.com"));
        assert!(!rendered.contains("kitrove-known-hosts-canary"));
        assert!(
            SshGitSyncBackend::open(
                "ssh://git@example.com/owner/repo.git",
                "relative-known-hosts",
            )
            .is_err()
        );
    }

    #[test]
    fn synchronous_boundary_fails_closed_inside_an_async_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_eq!(
                run_ssh_operation(async { Ok(()) }).unwrap_err().code(),
                "sync_backend.ssh_runtime_failed"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn satisfies_shared_backend_lifecycle_through_smart_ssh() {
        let fixture = ssh_contract_fixture();
        crate::sync_backend::tests::assert_backend_lifecycle_contract(&fixture.backend);
        assert!(fixture.scripts.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn connector_refuses_a_malformed_upload_advertisement() {
        let fixture = start_ssh_fixture(VecDeque::from([SshExchangeScript {
            command: UPLOAD_COMMAND,
            advertisement: b"zzzz".to_vec(),
            response: None,
        }]));
        assert!(fixture.backend.inspect(SyncLimits::default()).is_err());
        assert!(fixture.scripts.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn connector_refuses_a_malformed_selected_pack() {
        let selected = advertisement(
            b"1111111111111111111111111111111111111111 refs/heads/kitrove-sync-v1\0object-format=sha1 shallow no-progress ofs-delta\n",
        );
        let mut response = b"0000".to_vec();
        response.extend(pkt(b"NAK\n"));
        response.extend_from_slice(b"PACK-invalid");
        let fixture = start_ssh_fixture(VecDeque::from([SshExchangeScript {
            command: UPLOAD_COMMAND,
            advertisement: selected,
            response: Some(response),
        }]));
        assert!(fixture.backend.inspect(SyncLimits::default()).is_err());
        assert!(fixture.scripts.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn connector_never_claims_publication_from_a_malformed_receive_status() {
        let limits = SyncLimits::default();
        let fixture = start_ssh_fixture(VecDeque::from([SshExchangeScript {
            command: RECEIVE_COMMAND,
            advertisement: advertisement(
                b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 report-status\n",
            ),
            response: Some(b"0008nope0000".to_vec()),
        }]));
        let snapshot = empty_snapshot(limits);
        let publication =
            PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap();
        let intent = fixture
            .backend
            .prepare_publication(
                &RemoteRevision::parse("git:absent:v1").unwrap(),
                &publication,
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        assert_eq!(
            fixture
                .backend
                .publish(&intent, &snapshot, &[], limits)
                .unwrap(),
            PublicationStatus::Uncertain
        );
        assert!(fixture.scripts.lock().unwrap().is_empty());
    }
}
