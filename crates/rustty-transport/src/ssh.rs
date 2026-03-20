//! SSH transport helpers built on top of `russh`.

use std::{
    fmt, io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crossterm::terminal;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, Disconnect, client};
use ssh_key::{HashAlg, PublicKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};

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
            Self::Russh(source) => Some(source),
            Self::PrivateKeyLoad { source, .. } => Some(source),
            Self::MissingCommand
            | Self::AuthenticationRejected
            | Self::MissingAuthentication
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
    let (mut session, verified_host_key) = connect_authenticated_session(
        &request.host,
        request.port,
        &request.username,
        &request.authentication_methods,
        &request.host_key_check,
    )
    .await?;
    let mut local_forward_runtime = LocalForwardRuntime::start(&request.local_forwards).await?;

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
            Some(forward_request) = local_forward_runtime.connection_requests.recv(), if local_forward_runtime.enabled => {
                open_local_forward_channel(&session, forward_request, &mut local_forward_runtime).await?;
            }
            Some(forward_error) = local_forward_runtime.errors.recv(), if local_forward_runtime.enabled => {
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
    let (mut session, verified_host_key) = connect_authenticated_session(
        &request.host,
        request.port,
        &request.username,
        &request.authentication_methods,
        &request.host_key_check,
    )
    .await?;
    let mut local_forward_runtime = LocalForwardRuntime::start(&request.local_forwards).await?;

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
            Some(forward_request) = local_forward_runtime.connection_requests.recv(), if local_forward_runtime.enabled => {
                open_local_forward_channel(&session, forward_request, &mut local_forward_runtime).await?;
            }
            Some(forward_error) = local_forward_runtime.errors.recv(), if local_forward_runtime.enabled => {
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
            Some(forward_request) = local_forward_runtime.connection_requests.recv(), if local_forward_runtime.enabled => {
                open_local_forward_channel(&session, forward_request, &mut local_forward_runtime).await?;
            }
            Some(forward_error) = local_forward_runtime.errors.recv(), if local_forward_runtime.enabled => {
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
) -> Result<(client::Handle<ClientHandler>, VerifiedHostKey), TransportError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(15)),
        ..client::Config::default()
    });
    let state = Arc::new(Mutex::new(HostKeyState::default()));
    let handler = ClientHandler {
        host_key_check: host_key_check.clone(),
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
                let private_key = load_secret_key(private_key_path, key_passphrase.as_deref())
                    .map_err(|source| TransportError::PrivateKeyLoad {
                        path: private_key_path.clone(),
                        source,
                    })?;
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
        };

        if auth_result.success() {
            return Ok(());
        }
    }

    Err(TransportError::AuthenticationRejected)
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

struct LocalForwardRuntime {
    enabled: bool,
    connection_requests: mpsc::UnboundedReceiver<ForwardConnectionRequest>,
    errors: mpsc::UnboundedReceiver<TransportError>,
    error_sender: mpsc::UnboundedSender<TransportError>,
    accept_tasks: JoinSet<()>,
    bridge_tasks: JoinSet<()>,
}

impl LocalForwardRuntime {
    async fn start(local_forwards: &[SshLocalForwardSpec]) -> Result<Self, TransportError> {
        let (request_sender, connection_requests) = mpsc::unbounded_channel();
        let (error_sender, errors) = mpsc::unbounded_channel();
        let mut runtime = Self {
            enabled: !local_forwards.is_empty(),
            connection_requests,
            errors,
            error_sender: error_sender.clone(),
            accept_tasks: JoinSet::new(),
            bridge_tasks: JoinSet::new(),
        };

        for local_forward in local_forwards {
            let listen_address = render_socket_endpoint(
                local_forward.listen_host.as_str(),
                local_forward.listen_port,
            );
            let listener = TcpListener::bind(listen_address.as_str())
                .await
                .map_err(|source| TransportError::LocalForwardBind {
                    address: listen_address.clone(),
                    source,
                })?;
            let local_forward = local_forward.clone();
            let request_sender = request_sender.clone();
            let error_sender = error_sender.clone();
            runtime.accept_tasks.spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, originator_address)) => {
                            if request_sender
                                .send(ForwardConnectionRequest {
                                    local_forward: local_forward.clone(),
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
        }

        Ok(runtime)
    }
}

impl Drop for LocalForwardRuntime {
    fn drop(&mut self) {
        self.accept_tasks.abort_all();
        self.bridge_tasks.abort_all();
    }
}

struct ForwardConnectionRequest {
    local_forward: SshLocalForwardSpec,
    stream: TcpStream,
    originator_address: SocketAddr,
}

async fn open_local_forward_channel(
    session: &client::Handle<ClientHandler>,
    forward_request: ForwardConnectionRequest,
    local_forward_runtime: &mut LocalForwardRuntime,
) -> Result<(), TransportError> {
    let channel = session
        .channel_open_direct_tcpip(
            forward_request.local_forward.target_host.clone(),
            u32::from(forward_request.local_forward.target_port),
            forward_request.originator_address.ip().to_string(),
            u32::from(forward_request.originator_address.port()),
        )
        .await
        .map_err(TransportError::Russh)?;
    let error_sender = local_forward_runtime.error_sender.clone();
    local_forward_runtime.bridge_tasks.spawn(async move {
        if let Err(error) = bridge_local_forward_stream(forward_request.stream, channel).await {
            let _ = error_sender.send(error);
        }
    });
    Ok(())
}

async fn bridge_local_forward_stream(
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
    use std::path::PathBuf;

    use ssh_key::PublicKey;

    use super::{
        HostKeyCheck, SshAuthentication, SshExecRequest, SshLocalForwardSpec, TerminalSize,
        TransportError, VerifiedHostKeySource, execute_ssh_command,
    };

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
}
