//! SSH transport helpers built on top of `russh`.

use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crossterm::terminal;
#[cfg(unix)]
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, Disconnect, client, client::KeyboardInteractiveAuthResponse};
use ssh_key::{Algorithm, HashAlg, PublicKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTHENTICATION: u8 = 0x00;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_COMMAND_CONNECT: u8 = 0x01;
const SOCKS_ADDRESS_IPV4: u8 = 0x01;
const SOCKS_ADDRESS_DOMAIN: u8 = 0x03;
const SOCKS_ADDRESS_IPV6: u8 = 0x04;
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const DYNAMIC_FORWARD_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Host-key handling mode for the current transport attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostKeyCheck {
    /// Accept any host key for the current connection attempt.
    AcceptAny,
    /// Require the server key to match one of the stored keys.
    RequireMatch(Vec<PublicKey>),
    /// Accept an unknown host key and return it for persistence.
    TrustOnFirstUse,
}

/// Trust source for the host key accepted during the current connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedHostKeySource {
    /// The session bypassed verification with an unsafe override.
    UnsafeAcceptAny,
    /// The session matched an existing known-host entry.
    KnownHosts,
    /// The session accepted and exposed a first-seen host key.
    TrustOnFirstUse,
}

/// The server host key accepted for the current SSH session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHostKey {
    /// Accepted server public key.
    pub public_key: PublicKey,
    /// Why the key was trusted.
    pub source: VerifiedHostKeySource,
}

/// Supported SSH authentication methods for the current request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshAuthentication {
    /// Password authentication.
    Password {
        /// Secret password material.
        password: String,
    },
    /// OpenSSH private-key authentication.
    PublicKey {
        /// Path to the private-key file.
        private_key_path: PathBuf,
        /// Optional decrypted passphrase for the key file.
        key_passphrase: Option<String>,
    },
    /// Keyboard-interactive authentication with scripted responses.
    KeyboardInteractive {
        /// Ordered responses supplied to server prompts.
        responses: Vec<String>,
    },
    /// Authentication via an SSH agent socket.
    Agent {
        /// Explicit agent socket path or `None` to use `SSH_AUTH_SOCK`.
        socket_path: Option<PathBuf>,
    },
}

/// A locally listening SSH port-forwarding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshLocalForwardSpec {
    /// Local bind host.
    pub listen_host: String,
    /// Local bind port.
    pub listen_port: u16,
    /// Remote host reached through the SSH server.
    pub target_host: String,
    /// Remote target port reached through the SSH server.
    pub target_port: u16,
}

/// A locally listening dynamic SOCKS forwarding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshDynamicForwardSpec {
    /// Local bind host.
    pub listen_host: String,
    /// Local bind port.
    pub listen_port: u16,
}

/// A remotely listening SSH port-forwarding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshRemoteForwardSpec {
    /// Remote bind host.
    pub listen_host: String,
    /// Remote bind port.
    pub listen_port: u16,
    /// Local target host reached from the RusTTY client.
    pub target_host: String,
    /// Local target port reached from the RusTTY client.
    pub target_port: u16,
}

/// A request to run a single remote command over SSH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshExecRequest {
    /// Remote host name or address.
    pub host: String,
    /// Remote TCP port.
    pub port: u16,
    /// SSH username.
    pub username: String,
    /// Ordered SSH authentication methods to try.
    pub authentication_methods: Vec<SshAuthentication>,
    /// Command string sent through `exec`.
    pub command: String,
    /// Requested local forwarding listeners to keep open during the SSH session.
    pub local_forwards: Vec<SshLocalForwardSpec>,
    /// Requested remote forwarding listeners to keep open during the SSH session.
    pub remote_forwards: Vec<SshRemoteForwardSpec>,
    /// Requested dynamic SOCKS listeners to keep open during the SSH session.
    pub dynamic_forwards: Vec<SshDynamicForwardSpec>,
    /// Host-key handling mode for this request.
    pub host_key_check: HostKeyCheck,
}

/// A request to open an interactive shell with a remote PTY.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshShellRequest {
    /// Remote host name or address.
    pub host: String,
    /// Remote TCP port.
    pub port: u16,
    /// SSH username.
    pub username: String,
    /// Ordered SSH authentication methods to try.
    pub authentication_methods: Vec<SshAuthentication>,
    /// Terminal type sent in the PTY request.
    pub term_type: String,
    /// Initial terminal size sent in the PTY request.
    pub terminal_size: TerminalSize,
    /// Requested local forwarding listeners to keep open during the SSH session.
    pub local_forwards: Vec<SshLocalForwardSpec>,
    /// Requested remote forwarding listeners to keep open during the SSH session.
    pub remote_forwards: Vec<SshRemoteForwardSpec>,
    /// Requested dynamic SOCKS listeners to keep open during the SSH session.
    pub dynamic_forwards: Vec<SshDynamicForwardSpec>,
    /// Host-key handling mode for this request.
    pub host_key_check: HostKeyCheck,
}

/// Terminal size for PTY-backed SSH sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalSize {
    /// Text-mode columns.
    pub columns: u32,
    /// Text-mode rows.
    pub rows: u32,
    /// Pixel width if available.
    pub pixel_width: u32,
    /// Pixel height if available.
    pub pixel_height: u32,
}

impl TerminalSize {
    /// Captures the current local terminal size.
    pub fn from_current_terminal() -> io::Result<Self> {
        let (columns, rows) = terminal::size()?;
        Ok(Self {
            columns: u32::from(columns),
            rows: u32::from(rows),
            pixel_width: 0,
            pixel_height: 0,
        })
    }
}

/// Output captured from a completed SSH exec request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshExecResult {
    /// Remote standard output bytes.
    pub stdout: Vec<u8>,
    /// Remote standard error bytes.
    pub stderr: Vec<u8>,
    /// Remote process exit status.
    pub exit_status: u32,
    /// Server host key accepted for the SSH session.
    pub verified_host_key: VerifiedHostKey,
}

/// Result returned after an interactive SSH shell finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshShellResult {
    /// Remote shell exit status.
    pub exit_status: u32,
    /// Server host key accepted for the SSH session.
    pub verified_host_key: VerifiedHostKey,
}

/// Errors returned by RusTTY transport helpers.
#[derive(Debug)]
pub enum TransportError {
    /// The Tokio runtime could not be constructed.
    Runtime(io::Error),
    /// Local terminal or stdio operation failed.
    LocalIo(io::Error),
    /// Binding a local forwarding socket failed.
    LocalForwardBind {
        /// Bind address that failed.
        address: String,
        /// Underlying bind error.
        source: io::Error,
    },
    /// Accepting a local forwarding connection failed.
    LocalForwardAccept {
        /// Listener address that failed.
        address: String,
        /// Underlying accept error.
        source: io::Error,
    },
    /// Registering a remote forwarding listener on the SSH server failed.
    RemoteForwardRequest {
        /// Remote bind address that failed.
        address: String,
        /// Underlying SSH request error.
        source: russh::Error,
    },
    /// The SSH server returned a remote forwarded port outside the TCP range.
    RemoteForwardAssignedPort {
        /// Remote bind address that was requested.
        address: String,
        /// Assigned remote port returned by the SSH server.
        port: u32,
    },
    /// The request does not contain a command.
    MissingCommand,
    /// All configured authentication methods were rejected by the server.
    AuthenticationRejected,
    /// No SSH authentication methods were configured.
    MissingAuthentication,
    /// Loading a local private key failed.
    PrivateKeyLoad {
        /// Path of the key file that failed to load.
        path: PathBuf,
        /// Underlying key-loading error.
        source: russh::keys::Error,
    },
    /// Connecting to the configured SSH agent failed.
    AgentConnect {
        /// Explicit agent socket path, if one was configured.
        socket_path: Option<PathBuf>,
        /// Underlying agent connection error.
        source: russh::keys::Error,
    },
    /// Loading identities from the configured SSH agent failed.
    AgentIdentities {
        /// Explicit agent socket path, if one was configured.
        socket_path: Option<PathBuf>,
        /// Underlying agent query error.
        source: russh::keys::Error,
    },
    /// SSH agent authentication failed while signing or answering the server.
    AgentAuthentication {
        /// Explicit agent socket path, if one was configured.
        socket_path: Option<PathBuf>,
        /// Underlying authentication error.
        source: russh::AgentAuthError,
    },
    /// SSH-agent authentication is not supported on the current platform.
    AgentUnsupportedPlatform,
    /// The configured keyboard-interactive response list ended before the server prompts did.
    MissingKeyboardInteractiveResponses {
        /// Number of prompts requested by the server in the current round.
        requested_prompts: usize,
        /// Number of configured responses still available.
        available_responses: usize,
    },
    /// The remote command or shell completed without reporting an exit status.
    MissingExitStatus,
    /// The server did not expose a host key decision to the caller.
    MissingVerifiedHostKey,
    /// The server host key did not match any stored key.
    HostKeyMismatch {
        /// SHA-256 fingerprint of the server key.
        actual_fingerprint: String,
        /// Stored SHA-256 fingerprints that were expected.
        expected_fingerprints: Vec<String>,
    },
    /// SSH protocol or network failure.
    Russh(russh::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(source) => write!(formatter, "failed to start Tokio runtime: {source}"),
            Self::LocalIo(source) => write!(formatter, "local terminal I/O failed: {source}"),
            Self::LocalForwardBind { address, source } => {
                write!(
                    formatter,
                    "failed to bind local forward {address}: {source}"
                )
            }
            Self::LocalForwardAccept { address, source } => {
                write!(
                    formatter,
                    "local forward listener {address} failed while accepting a connection: {source}"
                )
            }
            Self::RemoteForwardRequest { address, source } => {
                write!(
                    formatter,
                    "failed to request remote forward {address}: {source}"
                )
            }
            Self::RemoteForwardAssignedPort { address, port } => {
                write!(
                    formatter,
                    "remote forward {address} returned unsupported assigned port {port}"
                )
            }
            Self::MissingCommand => write!(formatter, "missing remote command for SSH exec"),
            Self::AuthenticationRejected => {
                write!(formatter, "SSH authentication was rejected")
            }
            Self::MissingAuthentication => {
                write!(formatter, "missing SSH authentication method")
            }
            Self::PrivateKeyLoad { path, source } => {
                write!(
                    formatter,
                    "failed to load SSH private key {}: {source}",
                    path.display()
                )
            }
            Self::AgentConnect {
                socket_path,
                source,
            } => write!(
                formatter,
                "failed to connect to SSH agent {}: {source}",
                render_agent_socket_path(socket_path.as_ref())
            ),
            Self::AgentIdentities {
                socket_path,
                source,
            } => write!(
                formatter,
                "failed to read identities from SSH agent {}: {source}",
                render_agent_socket_path(socket_path.as_ref())
            ),
            Self::AgentAuthentication {
                socket_path,
                source,
            } => write!(
                formatter,
                "SSH agent authentication failed via {}: {source}",
                render_agent_socket_path(socket_path.as_ref())
            ),
            Self::AgentUnsupportedPlatform => {
                write!(
                    formatter,
                    "SSH-agent authentication is not supported on this platform yet"
                )
            }
            Self::MissingKeyboardInteractiveResponses {
                requested_prompts,
                available_responses,
            } => {
                write!(
                    formatter,
                    "keyboard-interactive authentication requested {requested_prompts} prompt responses but only {available_responses} remained configured"
                )
            }
            Self::MissingExitStatus => {
                write!(formatter, "remote session finished without an exit status")
            }
            Self::MissingVerifiedHostKey => {
                write!(
                    formatter,
                    "server host key was not recorded during SSH setup"
                )
            }
            Self::HostKeyMismatch {
                actual_fingerprint,
                expected_fingerprints,
            } => {
                write!(
                    formatter,
                    "server host key mismatch: expected one of [{}], got {}",
                    expected_fingerprints.join(", "),
                    actual_fingerprint
                )
            }
            Self::Russh(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(source)
            | Self::LocalIo(source)
            | Self::LocalForwardBind { source, .. }
            | Self::LocalForwardAccept { source, .. } => Some(source),
            Self::RemoteForwardRequest { source, .. } => Some(source),
            Self::Russh(source) => Some(source),
            Self::PrivateKeyLoad { source, .. } => Some(source),
            Self::AgentConnect { source, .. } | Self::AgentIdentities { source, .. } => {
                Some(source)
            }
            Self::AgentAuthentication { source, .. } => Some(source),
            Self::MissingCommand
            | Self::RemoteForwardAssignedPort { .. }
            | Self::AuthenticationRejected
            | Self::MissingAuthentication
            | Self::AgentUnsupportedPlatform
            | Self::MissingKeyboardInteractiveResponses { .. }
            | Self::MissingExitStatus
            | Self::MissingVerifiedHostKey
            | Self::HostKeyMismatch { .. } => None,
        }
    }
}

/// Executes a remote SSH command and captures stdout, stderr, and exit status.
pub fn execute_ssh_command(request: &SshExecRequest) -> Result<SshExecResult, TransportError> {
    if request.command.trim().is_empty() {
        return Err(TransportError::MissingCommand);
    }

    runtime()?.block_on(async_execute_ssh_command(request))
}

/// Runs an interactive SSH shell using the current process terminal.
pub fn run_interactive_shell(request: &SshShellRequest) -> Result<SshShellResult, TransportError> {
    runtime()?.block_on(async_run_interactive_shell(request))
}

async fn async_execute_ssh_command(
    request: &SshExecRequest,
) -> Result<SshExecResult, TransportError> {
    let (forward_request_sender, forward_connection_requests) = mpsc::unbounded_channel();
    let (mut session, verified_host_key) = connect_authenticated_session(
        &request.host,
        request.port,
        &request.username,
        &request.authentication_methods,
        &request.host_key_check,
        forward_request_sender.clone(),
    )
    .await?;
    let mut forward_runtime = ForwardRuntime::start(
        &session,
        &request.local_forwards,
        &request.remote_forwards,
        &request.dynamic_forwards,
        forward_request_sender,
        forward_connection_requests,
    )
    .await?;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(TransportError::Russh)?;
    channel
        .exec(true, request.command.as_str())
        .await
        .map_err(TransportError::Russh)?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;

    loop {
        tokio::select! {
            Some(forward_request) = forward_runtime.connection_requests.recv(), if forward_runtime.enabled => {
                open_forward_channel(&session, forward_request, &mut forward_runtime).await?;
            }
            Some(forward_error) = forward_runtime.errors.recv(), if forward_runtime.enabled => {
                return Err(forward_error);
            }
            maybe_message = channel.wait() => {
                let Some(message) = maybe_message else {
                    break;
                };

                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(data.as_ref()),
                    ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(data.as_ref()),
                    ChannelMsg::ExitStatus {
                        exit_status: status,
                    } => exit_status = Some(status),
                    ChannelMsg::ExitSignal {
                        signal_name,
                        error_message,
                        ..
                    } => {
                        if !error_message.is_empty() {
                            stderr.extend_from_slice(error_message.as_bytes());
                            stderr.push(b'\n');
                        }
                        stderr.extend_from_slice(
                            format!("remote exit signal: {signal_name:?}\n").as_bytes(),
                        );
                        exit_status.get_or_insert(128);
                    }
                    ChannelMsg::Close => break,
                    ChannelMsg::Eof
                    | ChannelMsg::Open { .. }
                    | ChannelMsg::OpenFailure(_)
                    | ChannelMsg::WindowAdjusted { .. }
                    | ChannelMsg::Success
                    | ChannelMsg::Failure
                    | ChannelMsg::XonXoff { .. }
                    | _ => {}
                }
            }
        }
    }

    disconnect_session(&mut session, "rusplink command completed").await;

    Ok(SshExecResult {
        stdout,
        stderr,
        exit_status: exit_status.ok_or(TransportError::MissingExitStatus)?,
        verified_host_key,
    })
}

async fn async_run_interactive_shell(
    request: &SshShellRequest,
) -> Result<SshShellResult, TransportError> {
    let (forward_request_sender, forward_connection_requests) = mpsc::unbounded_channel();
    let (mut session, verified_host_key) = connect_authenticated_session(
        &request.host,
        request.port,
        &request.username,
        &request.authentication_methods,
        &request.host_key_check,
        forward_request_sender.clone(),
    )
    .await?;
    let mut forward_runtime = ForwardRuntime::start(
        &session,
        &request.local_forwards,
        &request.remote_forwards,
        &request.dynamic_forwards,
        forward_request_sender,
        forward_connection_requests,
    )
    .await?;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(TransportError::Russh)?;
    channel
        .request_pty(
            true,
            request.term_type.as_str(),
            request.terminal_size.columns,
            request.terminal_size.rows,
            request.terminal_size.pixel_width,
            request.terminal_size.pixel_height,
            &[],
        )
        .await
        .map_err(TransportError::Russh)?;
    channel
        .request_shell(true)
        .await
        .map_err(TransportError::Russh)?;

    let _raw_mode = RawModeGuard::new()?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut buffer = [0_u8; 4096];
    let mut stdin_closed = false;
    let mut exit_status = None;

    #[cfg(unix)]
    let mut resize_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(TransportError::LocalIo)?;

    #[cfg(unix)]
    loop {
        tokio::select! {
            read_result = stdin.read(&mut buffer), if !stdin_closed => {
                match read_result {
                    Ok(0) => {
                        stdin_closed = true;
                        channel.eof().await.map_err(TransportError::Russh)?;
                    }
                    Ok(read_bytes) => channel
                        .data(&buffer[..read_bytes])
                        .await
                        .map_err(TransportError::Russh)?,
                    Err(source) => return Err(TransportError::LocalIo(source)),
                }
            }
            maybe_signal = resize_signal.recv() => {
                if maybe_signal.is_some() {
                    let size = TerminalSize::from_current_terminal().map_err(TransportError::LocalIo)?;
                    channel
                        .window_change(size.columns, size.rows, size.pixel_width, size.pixel_height)
                        .await
                        .map_err(TransportError::Russh)?;
                }
            }
            Some(forward_request) = forward_runtime.connection_requests.recv(), if forward_runtime.enabled => {
                open_forward_channel(&session, forward_request, &mut forward_runtime).await?;
            }
            Some(forward_error) = forward_runtime.errors.recv(), if forward_runtime.enabled => {
                return Err(forward_error);
            }
            maybe_message = channel.wait() => {
                if handle_shell_channel_message(
                    maybe_message,
                    &mut channel,
                    &mut stdout,
                    &mut stderr,
                    &mut exit_status,
                    &mut stdin_closed,
                )
                .await? {
                    break;
                }
            }
        }
    }

    #[cfg(not(unix))]
    loop {
        tokio::select! {
            read_result = stdin.read(&mut buffer), if !stdin_closed => {
                match read_result {
                    Ok(0) => {
                        stdin_closed = true;
                        channel.eof().await.map_err(TransportError::Russh)?;
                    }
                    Ok(read_bytes) => channel
                        .data(&buffer[..read_bytes])
                        .await
                        .map_err(TransportError::Russh)?,
                    Err(source) => return Err(TransportError::LocalIo(source)),
                }
            }
            Some(forward_request) = forward_runtime.connection_requests.recv(), if forward_runtime.enabled => {
                open_forward_channel(&session, forward_request, &mut forward_runtime).await?;
            }
            Some(forward_error) = forward_runtime.errors.recv(), if forward_runtime.enabled => {
                return Err(forward_error);
            }
            maybe_message = channel.wait() => {
                if handle_shell_channel_message(
                    maybe_message,
                    &mut channel,
                    &mut stdout,
                    &mut stderr,
                    &mut exit_status,
                    &mut stdin_closed,
                )
                .await? {
                    break;
                }
            }
        }
    }

    disconnect_session(&mut session, "rusplink shell completed").await;

    Ok(SshShellResult {
        exit_status: exit_status.ok_or(TransportError::MissingExitStatus)?,
        verified_host_key,
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, TransportError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(TransportError::Runtime)
}

async fn connect_authenticated_session(
    host: &str,
    port: u16,
    username: &str,
    authentication_methods: &[SshAuthentication],
    host_key_check: &HostKeyCheck,
    forward_request_sender: mpsc::UnboundedSender<ForwardConnectionRequest>,
) -> Result<(client::Handle<ClientHandler>, VerifiedHostKey), TransportError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(15)),
        ..client::Config::default()
    });
    let state = Arc::new(Mutex::new(HostKeyState::default()));
    let handler = ClientHandler {
        host_key_check: host_key_check.clone(),
        forward_request_sender,
        state: Arc::clone(&state),
    };

    let address = (host, port);
    let mut session = client::connect(config, address, handler)
        .await
        .map_err(|source| map_connect_error(source, &state))?;
    authenticate_session(&mut session, username, authentication_methods).await?;

    let verified_host_key = lock_state(&state)
        .verified_host_key
        .clone()
        .ok_or(TransportError::MissingVerifiedHostKey)?;

    Ok((session, verified_host_key))
}

async fn authenticate_session(
    session: &mut client::Handle<ClientHandler>,
    username: &str,
    authentication_methods: &[SshAuthentication],
) -> Result<(), TransportError> {
    if authentication_methods.is_empty() {
        return Err(TransportError::MissingAuthentication);
    }

    for authentication in authentication_methods {
        let auth_result = match authentication {
            SshAuthentication::Password { password } => session
                .authenticate_password(username.to_owned(), password.clone())
                .await
                .map_err(TransportError::Russh)?,
            SshAuthentication::PublicKey {
                private_key_path,
                key_passphrase,
            } => {
                let private_key =
                    load_private_key_file(private_key_path, key_passphrase.as_deref())?;
                let signature_hash = session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(TransportError::Russh)?
                    .flatten();
                session
                    .authenticate_publickey(
                        username.to_owned(),
                        PrivateKeyWithHashAlg::new(Arc::new(private_key), signature_hash),
                    )
                    .await
                    .map_err(TransportError::Russh)?
            }
            SshAuthentication::KeyboardInteractive { responses } => {
                if authenticate_keyboard_interactive(session, username, responses).await? {
                    return Ok(());
                }
                continue;
            }
            SshAuthentication::Agent { socket_path } => {
                if authenticate_agent(session, username, socket_path.as_ref()).await? {
                    return Ok(());
                }
                continue;
            }
        };

        if auth_result.success() {
            return Ok(());
        }
    }

    Err(TransportError::AuthenticationRejected)
}

fn load_private_key_file(
    private_key_path: &Path,
    key_passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey, TransportError> {
    load_secret_key(private_key_path, key_passphrase).map_err(|source| {
        TransportError::PrivateKeyLoad {
            path: private_key_path.to_path_buf(),
            source,
        }
    })
}

#[cfg(unix)]
async fn authenticate_agent(
    session: &mut client::Handle<ClientHandler>,
    username: &str,
    socket_path: Option<&PathBuf>,
) -> Result<bool, TransportError> {
    let mut agent = connect_agent_client(socket_path).await?;
    let identities =
        agent
            .request_identities()
            .await
            .map_err(|source| TransportError::AgentIdentities {
                socket_path: socket_path.cloned(),
                source,
            })?;

    if identities.is_empty() {
        return Ok(false);
    }

    let rsa_hash = session
        .best_supported_rsa_hash()
        .await
        .map_err(TransportError::Russh)?
        .flatten();

    for identity in identities {
        let hash_alg = match identity.algorithm() {
            Algorithm::Rsa { .. } => rsa_hash,
            _ => None,
        };
        let auth_result = session
            .authenticate_publickey_with(username.to_owned(), identity, hash_alg, &mut agent)
            .await
            .map_err(|source| TransportError::AgentAuthentication {
                socket_path: socket_path.cloned(),
                source,
            })?;
        if auth_result.success() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(unix))]
async fn authenticate_agent(
    _session: &mut client::Handle<ClientHandler>,
    _username: &str,
    _socket_path: Option<&PathBuf>,
) -> Result<bool, TransportError> {
    Err(TransportError::AgentUnsupportedPlatform)
}

#[cfg(unix)]
async fn connect_agent_client(
    socket_path: Option<&PathBuf>,
) -> Result<AgentClient<tokio::net::UnixStream>, TransportError> {
    match socket_path {
        Some(path) => {
            AgentClient::connect_uds(path)
                .await
                .map_err(|source| TransportError::AgentConnect {
                    socket_path: Some(path.clone()),
                    source,
                })
        }
        None => AgentClient::connect_env()
            .await
            .map_err(|source| TransportError::AgentConnect {
                socket_path: None,
                source,
            }),
    }
}

fn render_agent_socket_path(socket_path: Option<&PathBuf>) -> String {
    socket_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "SSH_AUTH_SOCK".to_owned())
}

async fn authenticate_keyboard_interactive(
    session: &mut client::Handle<ClientHandler>,
    username: &str,
    responses: &[String],
) -> Result<bool, TransportError> {
    let mut next_response_index = 0;
    let mut auth_response = session
        .authenticate_keyboard_interactive_start(username.to_owned(), None::<String>)
        .await
        .map_err(TransportError::Russh)?;

    loop {
        match auth_response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let available_responses = responses.len().saturating_sub(next_response_index);
                let requested_prompts = prompts.len();
                if available_responses < requested_prompts {
                    return Err(TransportError::MissingKeyboardInteractiveResponses {
                        requested_prompts,
                        available_responses,
                    });
                }

                let prompt_responses = responses
                    [next_response_index..next_response_index + requested_prompts]
                    .to_vec();
                next_response_index += requested_prompts;

                auth_response = session
                    .authenticate_keyboard_interactive_respond(prompt_responses)
                    .await
                    .map_err(TransportError::Russh)?;
            }
        }
    }
}

async fn handle_shell_channel_message(
    maybe_message: Option<ChannelMsg>,
    channel: &mut impl ShellChannel,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
    exit_status: &mut Option<u32>,
    stdin_closed: &mut bool,
) -> Result<bool, TransportError> {
    let Some(message) = maybe_message else {
        return Ok(true);
    };

    match message {
        ChannelMsg::Data { data } => {
            stdout
                .write_all(data.as_ref())
                .await
                .map_err(TransportError::LocalIo)?;
            stdout.flush().await.map_err(TransportError::LocalIo)?;
            Ok(false)
        }
        ChannelMsg::ExtendedData { data, .. } => {
            stderr
                .write_all(data.as_ref())
                .await
                .map_err(TransportError::LocalIo)?;
            stderr.flush().await.map_err(TransportError::LocalIo)?;
            Ok(false)
        }
        ChannelMsg::ExitStatus {
            exit_status: status,
        } => {
            *exit_status = Some(status);
            if !*stdin_closed {
                *stdin_closed = true;
                channel.eof().await.map_err(TransportError::Russh)?;
            }
            Ok(true)
        }
        ChannelMsg::ExitSignal {
            signal_name,
            error_message,
            ..
        } => {
            if !error_message.is_empty() {
                stderr
                    .write_all(error_message.as_bytes())
                    .await
                    .map_err(TransportError::LocalIo)?;
                stderr
                    .write_all(b"\n")
                    .await
                    .map_err(TransportError::LocalIo)?;
            }
            stderr
                .write_all(format!("remote exit signal: {signal_name:?}\n").as_bytes())
                .await
                .map_err(TransportError::LocalIo)?;
            stderr.flush().await.map_err(TransportError::LocalIo)?;
            exit_status.get_or_insert(128);
            Ok(false)
        }
        ChannelMsg::Close => Ok(true),
        ChannelMsg::Eof
        | ChannelMsg::Open { .. }
        | ChannelMsg::OpenFailure(_)
        | ChannelMsg::WindowAdjusted { .. }
        | ChannelMsg::Success
        | ChannelMsg::Failure
        | ChannelMsg::XonXoff { .. }
        | _ => Ok(false),
    }
}

async fn disconnect_session(session: &mut client::Handle<ClientHandler>, reason: &str) {
    let _ = session
        .disconnect(Disconnect::ByApplication, reason, "")
        .await;
}

struct ForwardRuntime {
    enabled: bool,
    connection_requests: mpsc::UnboundedReceiver<ForwardConnectionRequest>,
    errors: mpsc::UnboundedReceiver<TransportError>,
    error_sender: mpsc::UnboundedSender<TransportError>,
    accept_tasks: JoinSet<()>,
    bridge_tasks: JoinSet<()>,
    remote_forwards: Vec<RegisteredRemoteForward>,
}

impl ForwardRuntime {
    async fn start(
        session: &client::Handle<ClientHandler>,
        local_forwards: &[SshLocalForwardSpec],
        remote_forwards: &[SshRemoteForwardSpec],
        dynamic_forwards: &[SshDynamicForwardSpec],
        request_sender: mpsc::UnboundedSender<ForwardConnectionRequest>,
        connection_requests: mpsc::UnboundedReceiver<ForwardConnectionRequest>,
    ) -> Result<Self, TransportError> {
        let (error_sender, errors) = mpsc::unbounded_channel();
        let mut runtime = Self {
            enabled: !(local_forwards.is_empty()
                && remote_forwards.is_empty()
                && dynamic_forwards.is_empty()),
            connection_requests,
            errors,
            error_sender: error_sender.clone(),
            accept_tasks: JoinSet::new(),
            bridge_tasks: JoinSet::new(),
            remote_forwards: Vec::new(),
        };

        for local_forward in local_forwards {
            runtime
                .spawn_listener(
                    ForwardListenerSpec::Local(local_forward.clone()),
                    &request_sender,
                    &error_sender,
                )
                .await?;
        }

        for remote_forward in remote_forwards {
            runtime
                .register_remote_forward(session, remote_forward)
                .await?;
        }

        for dynamic_forward in dynamic_forwards {
            runtime
                .spawn_listener(
                    ForwardListenerSpec::Dynamic(dynamic_forward.clone()),
                    &request_sender,
                    &error_sender,
                )
                .await?;
        }

        Ok(runtime)
    }

    async fn spawn_listener(
        &mut self,
        listener_spec: ForwardListenerSpec,
        request_sender: &mpsc::UnboundedSender<ForwardConnectionRequest>,
        error_sender: &mpsc::UnboundedSender<TransportError>,
    ) -> Result<(), TransportError> {
        let listen_address = listener_spec.listen_address();
        let listener = TcpListener::bind(listen_address.as_str())
            .await
            .map_err(|source| TransportError::LocalForwardBind {
                address: listen_address.clone(),
                source,
            })?;
        let request_sender = request_sender.clone();
        let error_sender = error_sender.clone();
        self.accept_tasks.spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, originator_address)) => {
                        if request_sender
                            .send(ForwardConnectionRequest::LocalSocket {
                                kind: listener_spec.connection_kind(),
                                stream,
                                originator_address,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(source) => {
                        let _ = error_sender.send(TransportError::LocalForwardAccept {
                            address: listen_address.clone(),
                            source,
                        });
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    async fn register_remote_forward(
        &mut self,
        session: &client::Handle<ClientHandler>,
        remote_forward: &SshRemoteForwardSpec,
    ) -> Result<(), TransportError> {
        let requested_address = render_socket_endpoint(
            remote_forward.listen_host.as_str(),
            remote_forward.listen_port,
        );
        let assigned_port = session
            .tcpip_forward(
                remote_forward.listen_host.clone(),
                u32::from(remote_forward.listen_port),
            )
            .await
            .map_err(|source| TransportError::RemoteForwardRequest {
                address: requested_address.clone(),
                source,
            })?;
        let listen_port = if assigned_port == 0 {
            remote_forward.listen_port
        } else {
            u16::try_from(assigned_port).map_err(|_| TransportError::RemoteForwardAssignedPort {
                address: requested_address,
                port: assigned_port,
            })?
        };

        self.remote_forwards.push(RegisteredRemoteForward {
            listen_host: remote_forward.listen_host.clone(),
            listen_port,
            target_host: remote_forward.target_host.clone(),
            target_port: remote_forward.target_port,
        });
        Ok(())
    }

    fn find_remote_forward_target(
        &self,
        connected_address: &str,
        connected_port: u32,
    ) -> Option<RegisteredRemoteForward> {
        let connected_port = u16::try_from(connected_port).ok()?;

        if let Some(remote_forward) = self.remote_forwards.iter().find(|remote_forward| {
            remote_forward.listen_host == connected_address
                && remote_forward.listen_port == connected_port
        }) {
            return Some(remote_forward.clone());
        }

        let mut matches = self
            .remote_forwards
            .iter()
            .filter(|remote_forward| remote_forward.listen_port == connected_port);
        let first = matches.next()?;
        if matches.next().is_none() {
            Some(first.clone())
        } else {
            None
        }
    }
}

impl Drop for ForwardRuntime {
    fn drop(&mut self) {
        self.accept_tasks.abort_all();
        self.bridge_tasks.abort_all();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ForwardListenerSpec {
    Local(SshLocalForwardSpec),
    Dynamic(SshDynamicForwardSpec),
}

impl ForwardListenerSpec {
    fn listen_address(&self) -> String {
        match self {
            Self::Local(local_forward) => render_socket_endpoint(
                local_forward.listen_host.as_str(),
                local_forward.listen_port,
            ),
            Self::Dynamic(dynamic_forward) => render_socket_endpoint(
                dynamic_forward.listen_host.as_str(),
                dynamic_forward.listen_port,
            ),
        }
    }

    fn connection_kind(&self) -> ForwardConnectionKind {
        match self {
            Self::Local(local_forward) => ForwardConnectionKind::Local(local_forward.clone()),
            Self::Dynamic(dynamic_forward) => {
                ForwardConnectionKind::Dynamic(dynamic_forward.clone())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ForwardConnectionKind {
    Local(SshLocalForwardSpec),
    Dynamic(SshDynamicForwardSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegisteredRemoteForward {
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
}

struct IncomingRemoteForwardChannel {
    channel: russh::Channel<client::Msg>,
    connected_address: String,
    connected_port: u32,
}

enum ForwardConnectionRequest {
    LocalSocket {
        kind: ForwardConnectionKind,
        stream: TcpStream,
        originator_address: SocketAddr,
    },
    RemoteChannel(IncomingRemoteForwardChannel),
}

async fn open_forward_channel(
    session: &client::Handle<ClientHandler>,
    forward_request: ForwardConnectionRequest,
    forward_runtime: &mut ForwardRuntime,
) -> Result<(), TransportError> {
    match forward_request {
        ForwardConnectionRequest::LocalSocket {
            kind,
            stream,
            originator_address,
        } => match kind {
            ForwardConnectionKind::Local(local_forward) => {
                open_local_forward_channel(
                    session,
                    local_forward,
                    stream,
                    originator_address,
                    forward_runtime,
                )
                .await
            }
            ForwardConnectionKind::Dynamic(_dynamic_forward) => {
                open_dynamic_forward_channel(session, stream, originator_address, forward_runtime)
                    .await
            }
        },
        ForwardConnectionRequest::RemoteChannel(remote_channel) => {
            open_remote_forward_channel(remote_channel, forward_runtime).await
        }
    }
}

async fn open_local_forward_channel(
    session: &client::Handle<ClientHandler>,
    local_forward: SshLocalForwardSpec,
    stream: TcpStream,
    originator_address: SocketAddr,
    forward_runtime: &mut ForwardRuntime,
) -> Result<(), TransportError> {
    let channel = session
        .channel_open_direct_tcpip(
            local_forward.target_host,
            u32::from(local_forward.target_port),
            originator_address.ip().to_string(),
            u32::from(originator_address.port()),
        )
        .await
        .map_err(TransportError::Russh)?;
    let error_sender = forward_runtime.error_sender.clone();
    forward_runtime.bridge_tasks.spawn(async move {
        if let Err(error) = bridge_forward_stream(stream, channel).await {
            let _ = error_sender.send(error);
        }
    });
    Ok(())
}

async fn open_dynamic_forward_channel(
    session: &client::Handle<ClientHandler>,
    mut stream: TcpStream,
    originator_address: SocketAddr,
    forward_runtime: &mut ForwardRuntime,
) -> Result<(), TransportError> {
    let Some(target) = negotiate_socks5_target(&mut stream)
        .await
        .map_err(TransportError::LocalIo)?
    else {
        return Ok(());
    };

    let channel = match session
        .channel_open_direct_tcpip(
            target.host,
            u32::from(target.port),
            originator_address.ip().to_string(),
            u32::from(originator_address.port()),
        )
        .await
    {
        Ok(channel) => channel,
        Err(_) => {
            write_socks5_connect_reply(&mut stream, SOCKS_REPLY_GENERAL_FAILURE)
                .await
                .map_err(TransportError::LocalIo)?;
            return Ok(());
        }
    };

    write_socks5_connect_reply(&mut stream, SOCKS_REPLY_SUCCEEDED)
        .await
        .map_err(TransportError::LocalIo)?;
    forward_runtime.bridge_tasks.spawn(async move {
        let _ = bridge_forward_stream(stream, channel).await;
    });
    Ok(())
}

async fn open_remote_forward_channel(
    remote_channel: IncomingRemoteForwardChannel,
    forward_runtime: &mut ForwardRuntime,
) -> Result<(), TransportError> {
    let Some(target) = forward_runtime.find_remote_forward_target(
        remote_channel.connected_address.as_str(),
        remote_channel.connected_port,
    ) else {
        let _ = remote_channel.channel.close().await;
        return Ok(());
    };

    let target_address = render_socket_endpoint(target.target_host.as_str(), target.target_port);
    let stream = match TcpStream::connect(target_address.as_str()).await {
        Ok(stream) => stream,
        Err(_) => {
            let _ = remote_channel.channel.close().await;
            return Ok(());
        }
    };

    let error_sender = forward_runtime.error_sender.clone();
    forward_runtime.bridge_tasks.spawn(async move {
        if let Err(error) = bridge_forward_stream(stream, remote_channel.channel).await {
            let _ = error_sender.send(error);
        }
    });
    Ok(())
}

async fn bridge_forward_stream(
    mut stream: TcpStream,
    channel: russh::Channel<client::Msg>,
) -> Result<(), TransportError> {
    let mut channel_stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut channel_stream)
        .await
        .map_err(TransportError::LocalIo)?;
    channel_stream
        .shutdown()
        .await
        .map_err(TransportError::LocalIo)
}

struct SocksConnectTarget {
    host: String,
    port: u16,
}

async fn negotiate_socks5_target(stream: &mut TcpStream) -> io::Result<Option<SocksConnectTarget>> {
    let greeting = read_socks5_greeting(stream).await?;
    let Some(methods) = greeting else {
        return Ok(None);
    };

    if !methods.contains(&SOCKS_NO_AUTHENTICATION) {
        write_socks5_method_selection(stream, SOCKS_NO_ACCEPTABLE_METHODS).await?;
        return Ok(None);
    }

    write_socks5_method_selection(stream, SOCKS_NO_AUTHENTICATION).await?;
    read_socks5_connect_target(stream).await
}

async fn read_socks5_greeting(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 2];
    read_socks5_exact(stream, &mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Ok(None);
    }

    let method_count = usize::from(header[1]);
    if method_count == 0 {
        return Ok(Some(Vec::new()));
    }

    let mut methods = vec![0_u8; method_count];
    read_socks5_exact(stream, &mut methods).await?;
    Ok(Some(methods))
}

async fn read_socks5_connect_target(
    stream: &mut TcpStream,
) -> io::Result<Option<SocksConnectTarget>> {
    let mut header = [0_u8; 4];
    read_socks5_exact(stream, &mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Ok(None);
    }

    if header[1] != SOCKS_COMMAND_CONNECT {
        write_socks5_connect_reply(stream, SOCKS_REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Ok(None);
    }

    let address_type = header[3];
    let mut length_prefix = None;
    let address_length = match address_type {
        SOCKS_ADDRESS_IPV4 => 4,
        SOCKS_ADDRESS_DOMAIN => {
            let mut raw_length = [0_u8; 1];
            read_socks5_exact(stream, &mut raw_length).await?;
            length_prefix = Some(raw_length[0]);
            usize::from(raw_length[0])
        }
        SOCKS_ADDRESS_IPV6 => 16,
        _ => {
            write_socks5_connect_reply(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Ok(None);
        }
    };

    let mut address_bytes = vec![0_u8; address_length];
    read_socks5_exact(stream, &mut address_bytes).await?;
    let mut port_bytes = [0_u8; 2];
    read_socks5_exact(stream, &mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let Some(host) = decode_socks5_host(address_type, &address_bytes, length_prefix) else {
        write_socks5_connect_reply(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
        return Ok(None);
    };

    Ok(Some(SocksConnectTarget { host, port }))
}

fn decode_socks5_host(
    address_type: u8,
    address_bytes: &[u8],
    length_prefix: Option<u8>,
) -> Option<String> {
    match address_type {
        SOCKS_ADDRESS_IPV4 => {
            let octets: [u8; 4] = address_bytes.try_into().ok()?;
            Some(Ipv4Addr::from(octets).to_string())
        }
        SOCKS_ADDRESS_DOMAIN => {
            if length_prefix.is_some_and(|length| usize::from(length) != address_bytes.len()) {
                return None;
            }
            let host = String::from_utf8(address_bytes.to_vec()).ok()?;
            if host.is_empty() { None } else { Some(host) }
        }
        SOCKS_ADDRESS_IPV6 => {
            let octets: [u8; 16] = address_bytes.try_into().ok()?;
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

async fn read_socks5_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<()> {
    timeout(DYNAMIC_FORWARD_HANDSHAKE_TIMEOUT, stream.read_exact(buffer))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out while waiting for the SOCKS5 client handshake",
            )
        })?
        .map(|_| ())
}

async fn write_socks5_method_selection(stream: &mut TcpStream, method: u8) -> io::Result<()> {
    stream.write_all(&[SOCKS_VERSION, method]).await
}

async fn write_socks5_connect_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    stream
        .write_all(&[
            SOCKS_VERSION,
            reply,
            0x00,
            SOCKS_ADDRESS_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
}

fn render_socket_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn map_connect_error(source: russh::Error, state: &Arc<Mutex<HostKeyState>>) -> TransportError {
    if let Some(mismatch) = lock_state(state).host_key_mismatch.clone() {
        return TransportError::HostKeyMismatch {
            actual_fingerprint: mismatch.actual_fingerprint,
            expected_fingerprints: mismatch.expected_fingerprints,
        };
    }

    TransportError::Russh(source)
}

fn lock_state(state: &Arc<Mutex<HostKeyState>>) -> MutexGuard<'_, HostKeyState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn fingerprint(public_key: &PublicKey) -> String {
    public_key.fingerprint(HashAlg::Sha256).to_string()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HostKeyState {
    verified_host_key: Option<VerifiedHostKey>,
    host_key_mismatch: Option<HostKeyMismatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostKeyMismatch {
    actual_fingerprint: String,
    expected_fingerprints: Vec<String>,
}

struct ClientHandler {
    host_key_check: HostKeyCheck,
    forward_request_sender: mpsc::UnboundedSender<ForwardConnectionRequest>,
    state: Arc<Mutex<HostKeyState>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let mut state = lock_state(&self.state);

        match &self.host_key_check {
            HostKeyCheck::AcceptAny => {
                state.verified_host_key = Some(VerifiedHostKey {
                    public_key: server_public_key.clone(),
                    source: VerifiedHostKeySource::UnsafeAcceptAny,
                });
                Ok(true)
            }
            HostKeyCheck::RequireMatch(expected_keys) => {
                if expected_keys.iter().any(|key| key == server_public_key) {
                    state.verified_host_key = Some(VerifiedHostKey {
                        public_key: server_public_key.clone(),
                        source: VerifiedHostKeySource::KnownHosts,
                    });
                    return Ok(true);
                }

                state.host_key_mismatch = Some(HostKeyMismatch {
                    actual_fingerprint: fingerprint(server_public_key),
                    expected_fingerprints: expected_keys.iter().map(fingerprint).collect(),
                });
                Ok(false)
            }
            HostKeyCheck::TrustOnFirstUse => {
                state.verified_host_key = Some(VerifiedHostKey {
                    public_key: server_public_key.clone(),
                    source: VerifiedHostKeySource::TrustOnFirstUse,
                });
                Ok(true)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let request = ForwardConnectionRequest::RemoteChannel(IncomingRemoteForwardChannel {
            channel,
            connected_address: connected_address.to_owned(),
            connected_port,
        });
        if let Err(error) = self.forward_request_sender.send(request) {
            let ForwardConnectionRequest::RemoteChannel(remote_channel) = error.0 else {
                unreachable!("client handler only sends remote forward channels");
            };
            let _ = remote_channel.channel.close().await;
        }
        Ok(())
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Result<Self, TransportError> {
        terminal::enable_raw_mode().map_err(TransportError::LocalIo)?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

trait ShellChannel {
    fn eof(&mut self) -> impl std::future::Future<Output = Result<(), russh::Error>> + Send;
}

impl ShellChannel for russh::Channel<client::Msg> {
    fn eof(&mut self) -> impl std::future::Future<Output = Result<(), russh::Error>> + Send {
        russh::Channel::eof(self)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ssh_key::PublicKey;

    use super::{
        HostKeyCheck, SOCKS_ADDRESS_DOMAIN, SOCKS_ADDRESS_IPV4, SOCKS_ADDRESS_IPV6,
        SshAuthentication, SshDynamicForwardSpec, SshExecRequest, SshLocalForwardSpec,
        SshRemoteForwardSpec, TerminalSize, TransportError, VerifiedHostKeySource,
        decode_socks5_host, execute_ssh_command, load_private_key_file,
    };

    const PPK_FIXTURE: &str = include_str!("../../../tests/fixtures/keys/id_ed25519.ppk");
    const ENCRYPTED_PPK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/keys/id_ed25519_enc.ppk");

    #[test]
    fn rejects_missing_remote_command() {
        let request = SshExecRequest {
            host: "example.com".to_owned(),
            port: 22,
            username: "ops".to_owned(),
            authentication_methods: vec![SshAuthentication::Password {
                password: "secret".to_owned(),
            }],
            command: "   ".to_owned(),
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
            host_key_check: HostKeyCheck::AcceptAny,
        };

        assert!(matches!(
            execute_ssh_command(&request),
            Err(TransportError::MissingCommand)
        ));
    }

    #[test]
    fn terminal_size_is_plain_data() {
        let size = TerminalSize {
            columns: 120,
            rows: 40,
            pixel_width: 0,
            pixel_height: 0,
        };
        assert_eq!(size.columns, 120);
        assert_eq!(size.rows, 40);
    }

    #[test]
    fn host_key_check_keeps_multiple_expected_keys() {
        let expected_key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("sample key should parse");
        let check = HostKeyCheck::RequireMatch(vec![expected_key]);
        match check {
            HostKeyCheck::RequireMatch(keys) => assert_eq!(keys.len(), 1),
            HostKeyCheck::AcceptAny | HostKeyCheck::TrustOnFirstUse => {
                panic!("expected known-host verification")
            }
        }
    }

    #[test]
    fn verified_host_key_source_variants_are_stable() {
        assert_eq!(
            VerifiedHostKeySource::KnownHosts,
            VerifiedHostKeySource::KnownHosts
        );
    }

    #[test]
    fn public_key_auth_configuration_is_stable_data() {
        let authentication = SshAuthentication::PublicKey {
            private_key_path: PathBuf::from("/tmp/id_ed25519"),
            key_passphrase: Some("secret".to_owned()),
        };

        match authentication {
            SshAuthentication::PublicKey {
                private_key_path,
                key_passphrase,
            } => {
                assert_eq!(private_key_path, PathBuf::from("/tmp/id_ed25519"));
                assert_eq!(key_passphrase.as_deref(), Some("secret"));
            }
            SshAuthentication::Password { .. } => panic!("expected public-key auth"),
            SshAuthentication::KeyboardInteractive { .. } => {
                panic!("expected public-key auth")
            }
            SshAuthentication::Agent { .. } => panic!("expected public-key auth"),
        }
    }

    #[test]
    fn keyboard_interactive_auth_configuration_is_stable_data() {
        let authentication = SshAuthentication::KeyboardInteractive {
            responses: vec!["123456".to_owned(), "ops".to_owned()],
        };

        match authentication {
            SshAuthentication::KeyboardInteractive { responses } => {
                assert_eq!(responses, vec!["123456", "ops"]);
            }
            SshAuthentication::Password { .. }
            | SshAuthentication::PublicKey { .. }
            | SshAuthentication::Agent { .. } => {
                panic!("expected keyboard-interactive auth")
            }
        }
    }

    #[test]
    fn agent_auth_configuration_is_stable_data() {
        let authentication = SshAuthentication::Agent {
            socket_path: Some(PathBuf::from("/tmp/rusagent.sock")),
        };

        match authentication {
            SshAuthentication::Agent { socket_path } => {
                assert_eq!(socket_path, Some(PathBuf::from("/tmp/rusagent.sock")));
            }
            SshAuthentication::Password { .. }
            | SshAuthentication::PublicKey { .. }
            | SshAuthentication::KeyboardInteractive { .. } => {
                panic!("expected agent auth")
            }
        }
    }

    #[test]
    fn local_forward_spec_is_plain_data() {
        let forward = SshLocalForwardSpec {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 8080,
            target_host: "db.internal".to_owned(),
            target_port: 5432,
        };

        assert_eq!(forward.listen_host, "127.0.0.1");
        assert_eq!(forward.listen_port, 8080);
        assert_eq!(forward.target_host, "db.internal");
        assert_eq!(forward.target_port, 5432);
    }

    #[test]
    fn dynamic_forward_spec_is_plain_data() {
        let forward = SshDynamicForwardSpec {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 1080,
        };

        assert_eq!(forward.listen_host, "127.0.0.1");
        assert_eq!(forward.listen_port, 1080);
    }

    #[test]
    fn remote_forward_spec_is_plain_data() {
        let forward = SshRemoteForwardSpec {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 15432,
            target_host: "127.0.0.1".to_owned(),
            target_port: 5432,
        };

        assert_eq!(forward.listen_host, "127.0.0.1");
        assert_eq!(forward.listen_port, 15432);
        assert_eq!(forward.target_host, "127.0.0.1");
        assert_eq!(forward.target_port, 5432);
    }

    #[test]
    fn decode_socks5_host_supports_domain_targets() {
        let host = decode_socks5_host(
            SOCKS_ADDRESS_DOMAIN,
            b"db.internal",
            Some(b"db.internal".len() as u8),
        );

        assert_eq!(host.as_deref(), Some("db.internal"));
    }

    #[test]
    fn decode_socks5_host_supports_ip_targets() {
        let ipv4 = decode_socks5_host(SOCKS_ADDRESS_IPV4, &[127, 0, 0, 1], None);
        let ipv6 = decode_socks5_host(
            SOCKS_ADDRESS_IPV6,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            None,
        );

        assert_eq!(ipv4.as_deref(), Some("127.0.0.1"));
        assert_eq!(ipv6.as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn load_private_key_file_supports_putty_ppk_input() {
        let workspace = temporary_workspace();
        let key_path = workspace.join("id_ed25519.ppk");
        std::fs::write(&key_path, PPK_FIXTURE).expect("fixture should be written");

        let private_key =
            load_private_key_file(&key_path, None).expect("PPK private key should load");
        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(private_key.comment(), "user@example.com");
    }

    #[test]
    fn load_private_key_file_supports_encrypted_putty_ppk_input() {
        let workspace = temporary_workspace();
        let key_path = workspace.join("id_ed25519_enc.ppk");
        std::fs::write(&key_path, ENCRYPTED_PPK_FIXTURE).expect("fixture should be written");

        let private_key =
            load_private_key_file(&key_path, Some("123")).expect("encrypted PPK should load");
        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(private_key.comment(), "user@example.com");
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustty-transport-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
