use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kitrove_model::SyncLimits;
use russh::client;

use crate::BackendError;
#[cfg(unix)]
use crate::filesystem_identity::MetadataIdentity;
use crate::git_remote::{GitSshService, SshGitRemoteUrl};
use crate::git_sync_backend::{MAX_PACKET_LINE_BYTES, limit_exceeded, parse_hex_length};
#[cfg(unix)]
use crate::read_only_fs::{ReadOnlyRootOpen, open_root_nofollow, safe_metadata};
use crate::ssh_known_hosts::verify_known_host_file;

const MAX_AGENT_IDENTITIES: usize = 16;
const MAX_AUTHENTICATION_ATTEMPTS: usize = 8;
const SSH_CHANNEL_WINDOW_BYTES: u32 = 1024 * 1024;
const SSH_MAX_PACKET_BYTES: u32 = 32 * 1024;
const SSH_CHANNEL_BUFFER_MESSAGES: usize = 16;
const SSH_STDERR_BYTES: u64 = 64 * 1024;
#[cfg(windows)]
const WINDOWS_OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
const SSH_HOST_KEY_ALGORITHMS: &[russh::keys::Algorithm] = &[
    russh::keys::Algorithm::Ed25519,
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP256,
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP384,
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP521,
    },
];

struct HostKeyHandler {
    known_hosts: PathBuf,
    host: String,
    port: u16,
    failure: Arc<Mutex<Option<BackendError>>>,
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        match verify_known_host_file(&self.known_hosts, &self.host, self.port, server_key) {
            Ok(()) => Ok(true),
            Err(error) => {
                record_host_failure(&self.failure, error);
                Ok(false)
            }
        }
    }
}

pub(crate) struct SshServiceSession {
    _handle: client::Handle<HostKeyHandler>,
    channel: russh::Channel<client::Msg>,
    deadline: SshDeadline,
    stderr_bytes: u64,
}

impl SshServiceSession {
    pub(crate) async fn read_advertisement(
        &mut self,
        limits: SyncLimits,
    ) -> Result<Vec<u8>, BackendError> {
        let mut exchange =
            SshChannelExchange::new(limits.git().max_advertisement_bytes(), self.stderr_bytes);
        loop {
            let message = tokio::time::timeout(self.deadline.remaining()?, self.channel.wait())
                .await
                .map_err(|_| ssh_transport_failed())?
                .ok_or_else(ssh_transport_failed)?;
            exchange.accept_advertisement(message)?;
            if exchange.advertisement_complete()? {
                self.stderr_bytes = exchange.stderr_bytes;
                return Ok(exchange.stdout);
            }
        }
    }

    pub(crate) async fn exchange(
        &mut self,
        request: Vec<u8>,
        response_limit: u64,
        limits: SyncLimits,
    ) -> Result<Vec<u8>, BackendError> {
        if request.len() as u64 > limits.git().max_request_body_bytes() {
            return Err(limit_exceeded());
        }
        tokio::time::timeout(
            self.deadline.remaining()?,
            self.channel.data(request.as_slice()),
        )
        .await
        .map_err(|_| ssh_transport_failed())?
        .map_err(|_| ssh_transport_failed())?;
        tokio::time::timeout(self.deadline.remaining()?, self.channel.eof())
            .await
            .map_err(|_| ssh_transport_failed())?
            .map_err(|_| ssh_transport_failed())?;

        let mut exchange = SshChannelExchange::new(response_limit, self.stderr_bytes);
        loop {
            let message = tokio::time::timeout(self.deadline.remaining()?, self.channel.wait())
                .await
                .map_err(|_| ssh_transport_failed())?;
            match message {
                Some(message) => exchange.accept_response(message)?,
                None => return exchange.finish_after_channel_closed(),
            }
        }
    }
}

struct SshChannelExchange {
    stdout: Vec<u8>,
    stdout_limit: u64,
    stderr_bytes: u64,
    saw_eof: bool,
    saw_close: bool,
    exit_status: Option<u32>,
}

impl SshChannelExchange {
    const fn new(stdout_limit: u64, stderr_bytes: u64) -> Self {
        Self {
            stdout: Vec::new(),
            stdout_limit,
            stderr_bytes,
            saw_eof: false,
            saw_close: false,
            exit_status: None,
        }
    }

    fn accept_advertisement(&mut self, message: russh::ChannelMsg) -> Result<(), BackendError> {
        match message {
            russh::ChannelMsg::Data { data } => self.push_stdout(&data),
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => self.charge_stderr(data.len()),
            _ => Err(ssh_transport_failed()),
        }
    }

    fn advertisement_complete(&self) -> Result<bool, BackendError> {
        match packet_stream_end(&self.stdout)? {
            Some(end) if end == self.stdout.len() => Ok(true),
            Some(_) => Err(ssh_transport_failed()),
            None => Ok(false),
        }
    }

    fn accept_response(&mut self, message: russh::ChannelMsg) -> Result<(), BackendError> {
        if self.saw_close {
            return Err(ssh_transport_failed());
        }
        match message {
            russh::ChannelMsg::Data { data } if !self.saw_eof => self.push_stdout(&data),
            russh::ChannelMsg::ExtendedData { data, ext: 1 } if !self.saw_eof => {
                self.charge_stderr(data.len())
            }
            russh::ChannelMsg::Eof if !self.saw_eof => {
                self.saw_eof = true;
                Ok(())
            }
            russh::ChannelMsg::ExitStatus { exit_status } if self.exit_status.is_none() => {
                self.exit_status = Some(exit_status);
                Ok(())
            }
            russh::ChannelMsg::Close => {
                self.saw_close = true;
                Ok(())
            }
            _ => Err(ssh_transport_failed()),
        }
    }

    fn finish_after_channel_closed(self) -> Result<Vec<u8>, BackendError> {
        if self.saw_eof && self.exit_status == Some(0) {
            Ok(self.stdout)
        } else {
            Err(ssh_transport_failed())
        }
    }

    fn push_stdout(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        let next = (self.stdout.len() as u64)
            .checked_add(bytes.len() as u64)
            .ok_or_else(limit_exceeded)?;
        if next > self.stdout_limit {
            return Err(limit_exceeded());
        }
        self.stdout.extend_from_slice(bytes);
        Ok(())
    }

    fn charge_stderr(&mut self, bytes: usize) -> Result<(), BackendError> {
        self.stderr_bytes = self
            .stderr_bytes
            .checked_add(bytes as u64)
            .ok_or_else(limit_exceeded)?;
        if self.stderr_bytes > SSH_STDERR_BYTES {
            return Err(limit_exceeded());
        }
        Ok(())
    }
}

fn packet_stream_end(input: &[u8]) -> Result<Option<usize>, BackendError> {
    let mut offset = 0usize;
    loop {
        let Some(header) = input.get(offset..offset.saturating_add(4)) else {
            return Ok(None);
        };
        let length = parse_hex_length(header)?;
        if length == 0 {
            return Ok(Some(offset + 4));
        }
        if !(4..=MAX_PACKET_LINE_BYTES).contains(&length) {
            return Err(ssh_transport_failed());
        }
        let end = offset.checked_add(length).ok_or_else(limit_exceeded)?;
        if end > input.len() {
            return Ok(None);
        }
        offset = end;
    }
}

struct SshDeadline {
    expires: Instant,
}

impl SshDeadline {
    fn new(limits: SyncLimits) -> Result<Self, BackendError> {
        let duration = Duration::from_millis(limits.git().operation_deadline_ms());
        let expires = Instant::now()
            .checked_add(duration)
            .ok_or_else(ssh_transport_failed)?;
        Ok(Self { expires })
    }

    fn remaining(&self) -> Result<Duration, BackendError> {
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(ssh_transport_failed)
    }

    fn remaining_capped(&self, cap: Duration) -> Result<Duration, BackendError> {
        self.remaining().map(|remaining| remaining.min(cap))
    }
}

pub(crate) async fn open_ssh_service(
    remote: &SshGitRemoteUrl,
    known_hosts: &Path,
    service: GitSshService,
    limits: SyncLimits,
) -> Result<SshServiceSession, BackendError> {
    let (mut handle, deadline) = connect_verified(remote, known_hosts, limits).await?;
    authenticate_with_agent(&mut handle, remote.username().unwrap_or("git"), &deadline).await?;
    open_authenticated_service(handle, deadline, remote, service).await
}

#[cfg(all(test, unix))]
pub(crate) async fn open_ssh_service_with_agent_socket(
    remote: &SshGitRemoteUrl,
    known_hosts: &Path,
    agent_socket: &Path,
    service: GitSshService,
    limits: SyncLimits,
) -> Result<SshServiceSession, BackendError> {
    let (mut handle, deadline) = connect_verified(remote, known_hosts, limits).await?;
    authenticate_with_unix_agent_socket(
        &mut handle,
        remote.username().unwrap_or("git"),
        &deadline,
        agent_socket,
    )
    .await?;
    open_authenticated_service(handle, deadline, remote, service).await
}

async fn connect_verified(
    remote: &SshGitRemoteUrl,
    known_hosts: &Path,
    limits: SyncLimits,
) -> Result<(client::Handle<HostKeyHandler>, SshDeadline), BackendError> {
    let failure = Arc::new(Mutex::new(None));
    let handler = HostKeyHandler {
        known_hosts: known_hosts.to_owned(),
        host: remote.host().to_owned(),
        port: remote.port(),
        failure: Arc::clone(&failure),
    };
    let deadline = SshDeadline::new(limits)?;
    let config = Arc::new(client::Config {
        preferred: russh::Preferred {
            key: Cow::Borrowed(SSH_HOST_KEY_ALGORITHMS),
            ..russh::Preferred::DEFAULT
        },
        inactivity_timeout: Some(deadline.remaining()?),
        keepalive_interval: None,
        keepalive_max: 0,
        window_size: SSH_CHANNEL_WINDOW_BYTES,
        maximum_packet_size: SSH_MAX_PACKET_BYTES,
        channel_buffer_size: SSH_CHANNEL_BUFFER_MESSAGES,
        nodelay: false,
        ..<_>::default()
    });
    let connected = tokio::time::timeout(
        deadline.remaining_capped(Duration::from_millis(limits.git().connect_timeout_ms()))?,
        client::connect(config, (remote.host(), remote.port()), handler),
    )
    .await
    .map_err(|_| ssh_transport_failed())?;
    let handle = match connected {
        Ok(handle) => handle,
        Err(_) => {
            if let Some(error) = take_host_failure(&failure) {
                return Err(error);
            }
            return Err(ssh_transport_failed());
        }
    };
    Ok((handle, deadline))
}

async fn open_authenticated_service(
    handle: client::Handle<HostKeyHandler>,
    deadline: SshDeadline,
    remote: &SshGitRemoteUrl,
    service: GitSshService,
) -> Result<SshServiceSession, BackendError> {
    let mut channel = tokio::time::timeout(deadline.remaining()?, handle.channel_open_session())
        .await
        .map_err(|_| ssh_transport_failed())?
        .map_err(|_| ssh_transport_failed())?;
    tokio::time::timeout(
        deadline.remaining()?,
        channel.exec(true, remote.service_command(service)),
    )
    .await
    .map_err(|_| ssh_transport_failed())?
    .map_err(|_| ssh_transport_failed())?;
    let reply = tokio::time::timeout(deadline.remaining()?, channel.wait())
        .await
        .map_err(|_| ssh_transport_failed())?;
    if !matches!(reply, Some(russh::ChannelMsg::Success)) {
        return Err(ssh_transport_failed());
    }
    Ok(SshServiceSession {
        _handle: handle,
        channel,
        deadline,
        stderr_bytes: 0,
    })
}

#[cfg(unix)]
async fn authenticate_with_agent(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
) -> Result<(), BackendError> {
    let socket = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(ssh_authentication_failed)?;
    let socket = PathBuf::from(socket);
    authenticate_with_unix_agent_socket(handle, username, deadline, &socket).await
}

#[cfg(unix)]
async fn authenticate_with_unix_agent_socket(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
    socket: &Path,
) -> Result<(), BackendError> {
    use russh::keys::agent::client::AgentClient;

    authenticate_with_unix_agent_connector(handle, username, deadline, socket, |socket| async {
        AgentClient::connect_uds(socket).await
    })
    .await
}

#[cfg(unix)]
async fn authenticate_with_unix_agent_connector<C, F>(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
    socket: &Path,
    connect: C,
) -> Result<(), BackendError>
where
    C: FnOnce(PathBuf) -> F,
    F: std::future::Future<
            Output = Result<
                russh::keys::agent::client::AgentClient<tokio::net::UnixStream>,
                russh::keys::Error,
            >,
        >,
{
    if !socket.is_absolute()
        || socket
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ssh_authentication_failed());
    }
    let before = unix_agent_socket_identity(socket)?;
    let mut agent = tokio::time::timeout(deadline.remaining()?, connect(socket.to_owned()))
        .await
        .map_err(|_| ssh_authentication_failed())?
        .map_err(|_| ssh_authentication_failed())?;
    if unix_agent_socket_identity(socket)? != before {
        return Err(ssh_authentication_failed());
    }
    authenticate_identities(handle, username, deadline, &mut agent).await
}

#[cfg(unix)]
fn unix_agent_socket_identity(path: &Path) -> Result<MetadataIdentity, BackendError> {
    use cap_std::fs::FileTypeExt as _;

    let parent_path = path.parent().ok_or_else(ssh_authentication_failed)?;
    let name = path.file_name().ok_or_else(ssh_authentication_failed)?;
    let parent = match open_root_nofollow(parent_path) {
        ReadOnlyRootOpen::Open(parent) => parent,
        ReadOnlyRootOpen::Missing | ReadOnlyRootOpen::Unsafe => {
            return Err(ssh_authentication_failed());
        }
    };
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|_| ssh_authentication_failed())?;
    if !safe_metadata(&metadata) || !metadata.file_type().is_socket() {
        return Err(ssh_authentication_failed());
    }
    Ok(MetadataIdentity::from_metadata(&metadata))
}

#[cfg(windows)]
async fn authenticate_with_agent(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
) -> Result<(), BackendError> {
    authenticate_with_windows_agent_pipe(
        handle,
        username,
        deadline,
        std::ffi::OsStr::new(WINDOWS_OPENSSH_AGENT_PIPE),
    )
    .await
}

#[cfg(windows)]
async fn authenticate_with_windows_agent_pipe(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
    pipe: &std::ffi::OsStr,
) -> Result<(), BackendError> {
    use russh::keys::agent::client::AgentClient;

    let mut agent =
        tokio::time::timeout(deadline.remaining()?, AgentClient::connect_named_pipe(pipe))
            .await
            .map_err(|_| ssh_authentication_failed())?
            .map_err(|_| ssh_authentication_failed())?;
    authenticate_identities(handle, username, deadline, &mut agent).await
}

async fn authenticate_identities<S>(
    handle: &mut client::Handle<HostKeyHandler>,
    username: &str,
    deadline: &SshDeadline,
    agent: &mut russh::keys::agent::client::AgentClient<S>,
) -> Result<(), BackendError>
where
    S: russh::keys::agent::client::AgentStream + Send + Unpin + 'static,
{
    let identities = tokio::time::timeout(deadline.remaining()?, agent.request_identities())
        .await
        .map_err(|_| ssh_authentication_failed())?
        .map_err(|_| ssh_authentication_failed())?;
    if identities.is_empty() || identities.len() > MAX_AGENT_IDENTITIES {
        return Err(ssh_authentication_failed());
    }
    let mut attempts = 0usize;
    for identity in identities {
        let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = identity else {
            continue;
        };
        if key.algorithm().as_str().starts_with("ssh-rsa") {
            continue;
        }
        attempts += 1;
        if attempts > MAX_AUTHENTICATION_ATTEMPTS {
            break;
        }
        let result = tokio::time::timeout(
            deadline.remaining()?,
            handle.authenticate_publickey_with(username, key, None, agent),
        )
        .await
        .map_err(|_| ssh_authentication_failed())?
        .map_err(|_| ssh_authentication_failed())?;
        if result.success() {
            return Ok(());
        }
    }
    Err(ssh_authentication_failed())
}

fn record_host_failure(slot: &Mutex<Option<BackendError>>, error: BackendError) {
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(error);
    }
}

fn take_host_failure(slot: &Mutex<Option<BackendError>>) -> Option<BackendError> {
    slot.lock().ok()?.take()
}

const fn ssh_authentication_failed() -> BackendError {
    BackendError::new(
        "sync_backend.ssh_authentication_failed",
        "SSH agent authentication failed",
    )
}

const fn ssh_transport_failed() -> BackendError {
    BackendError::new("sync_backend.ssh_transport_failed", "SSH transport failed")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    use kitrove_model::GitSyncLimits;
    use kitrove_model::SyncLimits;
    use russh::ChannelMsg;
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{
        MAX_AGENT_IDENTITIES, MAX_AUTHENTICATION_ATTEMPTS, SSH_CHANNEL_BUFFER_MESSAGES,
        SSH_CHANNEL_WINDOW_BYTES, SSH_HOST_KEY_ALGORITHMS, SSH_MAX_PACKET_BYTES, SSH_STDERR_BYTES,
        SshChannelExchange, packet_stream_end,
    };

    fn test_private_key() -> russh::keys::PrivateKey {
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap()
    }

    #[derive(Clone)]
    struct AcceptingSshServer;

    impl russh::server::Server for AcceptingSshServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            self.clone()
        }
    }

    impl russh::server::Handler for AcceptingSshServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &russh::keys::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
    }

    #[cfg(unix)]
    #[derive(Clone)]
    struct ExchangeSshServer {
        advertisement: Vec<u8>,
        response: Vec<u8>,
        command: Arc<Mutex<Vec<u8>>>,
        request: Arc<Mutex<Vec<u8>>>,
    }

    #[cfg(unix)]
    impl russh::server::Server for ExchangeSshServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            self.clone()
        }
    }

    #[cfg(unix)]
    impl russh::server::Handler for ExchangeSshServer {
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
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.command.lock().unwrap().extend_from_slice(data);
            session.channel_success(channel)?;
            session.data(channel, self.advertisement.clone())?;
            Ok(())
        }

        async fn data(
            &mut self,
            _: russh::ChannelId,
            data: &[u8],
            _: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.request.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, self.response.clone())?;
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
            Ok(())
        }
    }

    #[cfg(unix)]
    struct AgentIncoming {
        listener: tokio::net::UnixListener,
        remaining: usize,
    }

    #[cfg(unix)]
    impl futures::Stream for AgentIncoming {
        type Item = std::io::Result<tokio::net::UnixStream>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            if self.remaining == 0 {
                return std::task::Poll::Ready(None);
            }
            match self.listener.poll_accept(context) {
                std::task::Poll::Ready(Ok((stream, _))) => {
                    self.remaining -= 1;
                    std::task::Poll::Ready(Some(Ok(stream)))
                }
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Some(Err(error))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    #[cfg(unix)]
    async fn start_test_agent<A>(socket: &Path, identities: &[russh::keys::PrivateKey], policy: A)
    where
        A: russh::keys::agent::server::Agent + Send + Sync + 'static,
    {
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        tokio::spawn(russh::keys::agent::server::serve(
            AgentIncoming {
                listener,
                remaining: 2,
            },
            policy,
        ));
        let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        let mut agent = russh::keys::agent::client::AgentClient::connect(stream);
        for identity in identities {
            agent.add_identity(identity, &[]).await.unwrap();
        }
    }

    #[cfg(unix)]
    async fn start_raw_test_agent(socket: &Path, reply: Option<Vec<u8>>) {
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request_length = stream.read_u32().await.unwrap();
            assert!(request_length <= 1024);
            let mut request = vec![0; request_length as usize];
            stream.read_exact(&mut request).await.unwrap();
            if let Some(reply) = reply {
                stream.write_all(&reply).await.unwrap();
            } else {
                std::future::pending::<()>().await;
            }
        });
    }

    #[cfg(windows)]
    async fn start_windows_test_agent(pipe: &str, identity: &russh::keys::PrivateKey) {
        use futures::channel::mpsc;
        use russh::keys::agent::client::AgentClient;
        use tokio::net::windows::named_pipe::ServerOptions;

        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe)
            .unwrap();
        let (incoming, connections) = mpsc::unbounded();
        let next_pipe = pipe.to_owned();
        tokio::spawn(async move {
            let mut waiting = Some(first);
            for create_next in [true, false] {
                let server = waiting.take().unwrap();
                server.connect().await.unwrap();
                let next = create_next.then(|| ServerOptions::new().create(&next_pipe).unwrap());
                incoming.unbounded_send(Ok(server)).unwrap();
                waiting = next;
            }
        });
        tokio::spawn(russh::keys::agent::server::serve(connections, ()));

        let mut agent = AgentClient::connect_named_pipe(pipe).await.unwrap();
        agent.add_identity(identity, &[]).await.unwrap();
    }

    #[cfg(unix)]
    fn ssh_deadline(operation_deadline_ms: u64) -> super::SshDeadline {
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
            defaults.response_header_timeout_ms(),
            defaults.body_read_timeout_ms(),
            operation_deadline_ms,
            operation_deadline_ms,
        )
        .unwrap();
        super::SshDeadline::new(SyncLimits::default().with_git_limits(git)).unwrap()
    }

    #[cfg(unix)]
    #[derive(Clone)]
    struct DenyAgentSigning;

    #[cfg(unix)]
    impl russh::keys::agent::server::Agent for DenyAgentSigning {
        fn confirm_request(
            &self,
            message: russh::keys::agent::server::MessageType,
        ) -> impl std::future::Future<Output = bool> + Send {
            let allowed = !matches!(message, russh::keys::agent::server::MessageType::Sign);
            async move { allowed }
        }
    }

    struct RunningTestServer {
        port: u16,
        handle: russh::server::RunningServerHandle,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    struct AgentBoundaryFixture {
        _server: RunningTestServer,
        _temporary: tempfile::TempDir,
        remote: crate::SshGitRemoteUrl,
        known_hosts: PathBuf,
        agent_socket: PathBuf,
        command: Arc<Mutex<Vec<u8>>>,
    }

    #[cfg(unix)]
    impl AgentBoundaryFixture {
        fn new(socket_name: &str) -> Self {
            let host_key = test_private_key();
            let authority = host_key.public_key().to_openssh().unwrap();
            let command = Arc::new(Mutex::new(Vec::new()));
            let server = start_test_server(
                ExchangeSshServer {
                    advertisement: Vec::new(),
                    response: Vec::new(),
                    command: Arc::clone(&command),
                    request: Arc::new(Mutex::new(Vec::new())),
                },
                host_key,
            );
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let known_hosts = root.join("known_hosts");
            let agent_socket = root.join(socket_name);
            std::fs::write(
                &known_hosts,
                format!("[localhost]:{} {authority}\n", server.port),
            )
            .unwrap();
            let remote = crate::SshGitRemoteUrl::parse(&format!(
                "ssh://git@localhost:{}/owner/repo.git",
                server.port
            ))
            .unwrap();
            Self {
                _server: server,
                _temporary: temporary,
                remote,
                known_hosts,
                agent_socket,
                command,
            }
        }

        async fn authenticate(
            &self,
            operation_deadline_ms: u64,
        ) -> Result<(), crate::BackendError> {
            let (mut ssh, _) =
                super::connect_verified(&self.remote, &self.known_hosts, SyncLimits::default())
                    .await?;
            let deadline = ssh_deadline(operation_deadline_ms);
            super::authenticate_with_unix_agent_socket(
                &mut ssh,
                "git",
                &deadline,
                &self.agent_socket,
            )
            .await
        }
    }

    impl Drop for RunningTestServer {
        fn drop(&mut self) {
            self.handle.shutdown("test complete".to_owned());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn start_test_server<S>(mut server: S, host_key: russh::keys::PrivateKey) -> RunningTestServer
    where
        S: russh::server::Server + Send + 'static,
    {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            ..<_>::default()
        });
        let (handle_sender, handle_receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let running = server.run_on_socket(config, &listener);
                handle_sender.send(running.handle()).unwrap();
                running.await.unwrap();
            });
        });
        RunningTestServer {
            port,
            handle: handle_receiver.recv().unwrap(),
            thread: Some(thread),
        }
    }

    #[test]
    fn authentication_and_protocol_limits_are_fixed_and_small() {
        assert_eq!(MAX_AGENT_IDENTITIES, 16);
        assert_eq!(MAX_AUTHENTICATION_ATTEMPTS, 8);
        assert_eq!(SSH_CHANNEL_WINDOW_BYTES, 1024 * 1024);
        assert_eq!(SSH_MAX_PACKET_BYTES, 32 * 1024);
        assert_eq!(SSH_CHANNEL_BUFFER_MESSAGES, 16);
        assert_eq!(SSH_HOST_KEY_ALGORITHMS.len(), 4);
        assert!(
            SSH_HOST_KEY_ALGORITHMS
                .iter()
                .all(|algorithm| !algorithm.as_str().contains("rsa"))
        );
        assert!(SyncLimits::default().git().operation_deadline_ms() > 0);
    }

    #[test]
    fn advertisement_boundary_accepts_fragmentation_but_rejects_suffixes() {
        assert_eq!(packet_stream_end(b"0031").unwrap(), None);
        assert_eq!(packet_stream_end(b"0008test0000").unwrap(), Some(12));
        assert!(packet_stream_end(b"zzzz").is_err());

        let mut exchange = SshChannelExchange::new(32, 0);
        exchange
            .accept_advertisement(ChannelMsg::Data {
                data: b"0008test".as_slice().into(),
            })
            .unwrap();
        assert!(!exchange.advertisement_complete().unwrap());
        exchange
            .accept_advertisement(ChannelMsg::Data {
                data: b"0000".as_slice().into(),
            })
            .unwrap();
        assert!(exchange.advertisement_complete().unwrap());

        exchange.stdout.push(b'x');
        assert!(exchange.advertisement_complete().is_err());
    }

    #[test]
    fn response_requires_bounded_output_and_exact_successful_termination() {
        let mut exchange = SshChannelExchange::new(4, 0);
        exchange
            .accept_response(ChannelMsg::Data {
                data: b"PACK".as_slice().into(),
            })
            .unwrap();
        exchange
            .accept_response(ChannelMsg::ExtendedData {
                data: b"notice".as_slice().into(),
                ext: 1,
            })
            .unwrap();
        exchange.accept_response(ChannelMsg::Eof).unwrap();
        exchange
            .accept_response(ChannelMsg::ExitStatus { exit_status: 0 })
            .unwrap();
        exchange.accept_response(ChannelMsg::Close).unwrap();
        assert_eq!(exchange.finish_after_channel_closed().unwrap(), b"PACK");

        let mut implicit_close = SshChannelExchange::new(0, 0);
        implicit_close.accept_response(ChannelMsg::Eof).unwrap();
        implicit_close
            .accept_response(ChannelMsg::ExitStatus { exit_status: 0 })
            .unwrap();
        assert!(implicit_close.finish_after_channel_closed().is_ok());

        let mut too_large = SshChannelExchange::new(3, 0);
        assert!(
            too_large
                .accept_response(ChannelMsg::Data {
                    data: b"PACK".as_slice().into(),
                })
                .is_err()
        );

        let mut stderr = SshChannelExchange::new(0, SSH_STDERR_BYTES);
        assert!(
            stderr
                .accept_response(ChannelMsg::ExtendedData {
                    data: b"x".as_slice().into(),
                    ext: 1,
                })
                .is_err()
        );
        let mut wrong_extended_stream = SshChannelExchange::new(0, 0);
        assert!(
            wrong_extended_stream
                .accept_response(ChannelMsg::ExtendedData {
                    data: b"x".as_slice().into(),
                    ext: 2,
                })
                .is_err()
        );

        let mut failed = SshChannelExchange::new(0, 0);
        failed.accept_response(ChannelMsg::Eof).unwrap();
        failed
            .accept_response(ChannelMsg::ExitStatus { exit_status: 1 })
            .unwrap();
        failed.accept_response(ChannelMsg::Close).unwrap();
        assert!(failed.finish_after_channel_closed().is_err());
    }

    #[test]
    fn real_handshake_rejects_host_authority_before_agent_authentication() {
        let host_key = test_private_key();
        let wrong_key = test_private_key();
        let server = start_test_server(AcceptingSshServer, host_key);
        let port = server.port;

        let temporary = tempfile::tempdir().unwrap();
        let known_hosts = temporary.path().canonicalize().unwrap().join("known_hosts");
        let wrong_authority = wrong_key.public_key().to_openssh().unwrap();
        std::fs::write(
            &known_hosts,
            format!("[localhost]:{port} {wrong_authority}\n"),
        )
        .unwrap();
        let remote =
            crate::SshGitRemoteUrl::parse(&format!("ssh://git@localhost:{port}/owner/repo.git"))
                .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = match runtime.block_on(super::open_ssh_service(
            &remote,
            &known_hosts,
            crate::git_remote::GitSshService::UploadPack,
            SyncLimits::default(),
        )) {
            Ok(_) => panic!("changed host authority must fail before authentication"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "sync_backend.ssh_host_key_changed");

        drop(server);
    }

    #[cfg(windows)]
    #[test]
    fn windows_openssh_named_pipe_agent_authenticates_through_production_protocol() {
        static PIPE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let host_key = test_private_key();
        let authority = host_key.public_key().to_openssh().unwrap();
        let server = start_test_server(AcceptingSshServer, host_key);
        let temporary = tempfile::tempdir().unwrap();
        let known_hosts = temporary.path().canonicalize().unwrap().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!("[localhost]:{} {authority}\n", server.port),
        )
        .unwrap();
        let remote = crate::SshGitRemoteUrl::parse(&format!(
            "ssh://git@localhost:{}/owner/repo.git",
            server.port
        ))
        .unwrap();
        let pipe = format!(
            r"\\.\pipe\kitrove-agent-test-{}-{}",
            std::process::id(),
            PIPE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let identity = test_private_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            start_windows_test_agent(&pipe, &identity).await;
            let limits = SyncLimits::default();
            let (mut ssh, deadline) = super::connect_verified(&remote, &known_hosts, limits)
                .await
                .unwrap();
            super::authenticate_with_windows_agent_pipe(
                &mut ssh,
                "git",
                &deadline,
                std::ffi::OsStr::new(&pipe),
            )
            .await
            .unwrap();
        });

        drop(server);
    }

    #[cfg(unix)]
    #[test]
    fn real_authenticated_channel_uses_exact_command_and_metered_bytes() {
        let host_key = test_private_key();
        let user_key = test_private_key();
        let command = Arc::new(Mutex::new(Vec::new()));
        let request = Arc::new(Mutex::new(Vec::new()));
        let server_state = ExchangeSshServer {
            advertisement: b"0008test0000".to_vec(),
            response: b"response".to_vec(),
            command: Arc::clone(&command),
            request: Arc::clone(&request),
        };
        let authority = host_key.public_key().to_openssh().unwrap();
        let server = start_test_server(server_state, host_key);
        let port = server.port;

        let temporary = tempfile::tempdir().unwrap();
        let temporary_root = temporary.path().canonicalize().unwrap();
        let known_hosts = temporary_root.join("known_hosts");
        let agent_socket = temporary_root.join("agent.sock");
        std::fs::write(&known_hosts, format!("[localhost]:{port} {authority}\n")).unwrap();
        let remote =
            crate::SshGitRemoteUrl::parse(&format!("ssh://git@localhost:{port}/owner/repo.git"))
                .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            start_test_agent(&agent_socket, &[user_key], ()).await;

            let limits = SyncLimits::default();
            let (mut ssh, deadline) = super::connect_verified(&remote, &known_hosts, limits)
                .await
                .unwrap();
            super::authenticate_with_unix_agent_socket(
                &mut ssh,
                remote.username().unwrap(),
                &deadline,
                &agent_socket,
            )
            .await
            .unwrap();
            let mut session = super::open_authenticated_service(
                ssh,
                deadline,
                &remote,
                crate::git_remote::GitSshService::UploadPack,
            )
            .await
            .unwrap();
            assert_eq!(
                session
                    .read_advertisement(SyncLimits::default())
                    .await
                    .unwrap(),
                b"0008test0000"
            );
            assert_eq!(
                session
                    .exchange(b"request".to_vec(), 8, SyncLimits::default())
                    .await
                    .unwrap(),
                b"response"
            );
        });
        assert_eq!(
            &*command.lock().unwrap(),
            b"git-upload-pack '/owner/repo.git'"
        );
        assert_eq!(&*request.lock().unwrap(), b"request");

        drop(server);
    }

    #[cfg(unix)]
    #[test]
    fn production_agent_boundary_rejects_excessive_identities_before_authentication() {
        let fixture = AgentBoundaryFixture::new("agent-excessive-identities.sock");
        let identities: Vec<_> = (0..=MAX_AGENT_IDENTITIES)
            .map(|_| test_private_key())
            .collect();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            start_test_agent(&fixture.agent_socket, &identities, ()).await;
            fixture
                .authenticate(SyncLimits::default().git().operation_deadline_ms())
                .await
                .unwrap_err()
        });
        assert_eq!(error.code(), "sync_backend.ssh_authentication_failed");
        assert!(fixture.command.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn production_agent_boundary_redacts_signing_refusal() {
        let fixture = AgentBoundaryFixture::new("agent-signing-refusal-canary.sock");
        let identity = test_private_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            start_test_agent(&fixture.agent_socket, &[identity], DenyAgentSigning).await;
            fixture
                .authenticate(SyncLimits::default().git().operation_deadline_ms())
                .await
                .unwrap_err()
        });
        assert_eq!(error.code(), "sync_backend.ssh_authentication_failed");
        assert!(!format!("{error:?}").contains("signing-refusal-canary"));
        assert!(fixture.command.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn production_agent_boundary_rejects_malformed_frames() {
        let fixture = AgentBoundaryFixture::new("agent-malformed-frame-canary.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            start_raw_test_agent(&fixture.agent_socket, Some(vec![0, 0, 0, 1, 0xff])).await;
            fixture.authenticate(1_000).await.unwrap_err()
        });
        assert_eq!(error.code(), "sync_backend.ssh_authentication_failed");
        assert!(!format!("{error:?}").contains("malformed-frame-canary"));
        assert!(fixture.command.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn production_agent_boundary_applies_the_operation_deadline() {
        let fixture = AgentBoundaryFixture::new("agent-deadline-canary.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            start_raw_test_agent(&fixture.agent_socket, None).await;
            fixture.authenticate(50).await.unwrap_err()
        });
        assert_eq!(error.code(), "sync_backend.ssh_authentication_failed");
        assert!(!format!("{error:?}").contains("deadline-canary"));
        assert!(fixture.command.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn production_agent_boundary_rejects_socket_replacement() {
        use russh::keys::agent::client::AgentClient;

        let fixture = AgentBoundaryFixture::new("agent-replacement-canary.sock");
        let identity = test_private_key();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            start_test_agent(&fixture.agent_socket, &[identity], ()).await;
            let (mut ssh, _) = super::connect_verified(
                &fixture.remote,
                &fixture.known_hosts,
                SyncLimits::default(),
            )
            .await
            .unwrap();
            super::authenticate_with_unix_agent_connector(
                &mut ssh,
                "git",
                &super::SshDeadline::new(SyncLimits::default()).unwrap(),
                &fixture.agent_socket,
                |socket| async move {
                    let agent = AgentClient::connect_uds(&socket).await?;
                    std::fs::remove_file(&socket).map_err(russh::keys::Error::IO)?;
                    let replacement =
                        tokio::net::UnixListener::bind(&socket).map_err(russh::keys::Error::IO)?;
                    drop(replacement);
                    Ok(agent)
                },
            )
            .await
            .unwrap_err()
        });
        assert_eq!(error.code(), "sync_backend.ssh_authentication_failed");
        assert!(!format!("{error:?}").contains("replacement-canary"));
        assert!(fixture.command.lock().unwrap().is_empty());
    }
}
