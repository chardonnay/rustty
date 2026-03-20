//! SSH transport helpers built on top of `russh`.

use std::{fmt, sync::Arc, time::Duration};

use russh::{ChannelMsg, Disconnect, client};

/// Host-key handling mode for the current transport attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyCheck {
    /// Accept any host key for the current connection attempt.
    AcceptAny,
    /// Reject the host key and abort the connection.
    Reject,
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
    /// Password used for SSH password authentication.
    pub password: String,
    /// Command string sent through `exec`.
    pub command: String,
    /// Host-key handling mode for this request.
    pub host_key_check: HostKeyCheck,
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
}

/// Errors returned by RusTTY transport helpers.
#[derive(Debug)]
pub enum TransportError {
    /// The Tokio runtime could not be constructed.
    Runtime(std::io::Error),
    /// The request does not contain a command.
    MissingCommand,
    /// Password-based authentication was rejected by the server.
    AuthenticationRejected,
    /// The remote command completed without reporting an exit status.
    MissingExitStatus,
    /// SSH protocol or network failure.
    Russh(russh::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(source) => write!(formatter, "failed to start Tokio runtime: {source}"),
            Self::MissingCommand => write!(formatter, "missing remote command for SSH exec"),
            Self::AuthenticationRejected => {
                write!(formatter, "SSH password authentication was rejected")
            }
            Self::MissingExitStatus => {
                write!(formatter, "remote command finished without an exit status")
            }
            Self::Russh(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(source) => Some(source),
            Self::Russh(source) => Some(source),
            Self::MissingCommand | Self::AuthenticationRejected | Self::MissingExitStatus => None,
        }
    }
}

/// Executes a remote SSH command and captures stdout, stderr, and exit status.
pub fn execute_ssh_command(request: &SshExecRequest) -> Result<SshExecResult, TransportError> {
    if request.command.trim().is_empty() {
        return Err(TransportError::MissingCommand);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(TransportError::Runtime)?;
    runtime.block_on(async_execute_ssh_command(request))
}

async fn async_execute_ssh_command(
    request: &SshExecRequest,
) -> Result<SshExecResult, TransportError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(15)),
        ..client::Config::default()
    });

    let handler = ClientHandler {
        host_key_check: request.host_key_check,
    };
    let address = (request.host.as_str(), request.port);
    let mut session = client::connect(config, address, handler)
        .await
        .map_err(TransportError::Russh)?;
    let auth_result = session
        .authenticate_password(request.username.clone(), request.password.clone())
        .await
        .map_err(TransportError::Russh)?;

    if !auth_result.success() {
        return Err(TransportError::AuthenticationRejected);
    }

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

    while let Some(message) = channel.wait().await {
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
                stderr
                    .extend_from_slice(format!("remote exit signal: {signal_name:?}\n").as_bytes());
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

    let _ = session
        .disconnect(Disconnect::ByApplication, "rusplink command completed", "")
        .await;

    Ok(SshExecResult {
        stdout,
        stderr,
        exit_status: exit_status.ok_or(TransportError::MissingExitStatus)?,
    })
}

struct ClientHandler {
    host_key_check: HostKeyCheck,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(self.host_key_check, HostKeyCheck::AcceptAny))
    }
}

#[cfg(test)]
mod tests {
    use super::{HostKeyCheck, SshExecRequest, TransportError, execute_ssh_command};

    #[test]
    fn rejects_missing_remote_command() {
        let request = SshExecRequest {
            host: "example.com".to_owned(),
            port: 22,
            username: "ops".to_owned(),
            password: "secret".to_owned(),
            command: "   ".to_owned(),
            host_key_check: HostKeyCheck::AcceptAny,
        };

        assert!(matches!(
            execute_ssh_command(&request),
            Err(TransportError::MissingCommand)
        ));
    }
}
