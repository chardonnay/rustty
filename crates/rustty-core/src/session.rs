//! Session and protocol types shared by RusTTY tools.

use serde::{Deserialize, Serialize};

/// Supported protocols and tool-facing service modes in the RusTTY roadmap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// SSH terminal and command sessions.
    Ssh,
    /// Secure Copy over SSH.
    Scp,
    /// SSH File Transfer Protocol.
    Sftp,
    /// Telnet sessions.
    Telnet,
    /// Raw TCP sessions.
    Raw,
    /// Rlogin sessions.
    Rlogin,
    /// Serial line sessions.
    Serial,
    /// Agent service interactions.
    Agent,
    /// Key-generation and conversion workflows.
    Keygen,
}

impl Protocol {
    /// Returns a human-readable label for the protocol.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Scp => "SCP",
            Self::Sftp => "SFTP",
            Self::Telnet => "Telnet",
            Self::Raw => "Raw",
            Self::Rlogin => "Rlogin",
            Self::Serial => "Serial",
            Self::Agent => "Agent",
            Self::Keygen => "Keygen",
        }
    }

    /// Returns the default port for protocols that use one.
    #[must_use]
    pub const fn default_port(self) -> Option<u16> {
        match self {
            Self::Ssh | Self::Scp | Self::Sftp => Some(22),
            Self::Telnet => Some(23),
            Self::Rlogin => Some(513),
            Self::Raw | Self::Serial | Self::Agent | Self::Keygen => None,
        }
    }
}

/// Host key trust policies for SSH-family sessions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    /// Prompt before trusting an unknown host key.
    Ask,
    /// Require a pre-trusted host key.
    Strict,
    /// Trust new host keys on first use.
    AcceptNew,
}

/// Configuration storage formats relevant to migration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFormat {
    /// RusTTY-native storage.
    Rustty,
    /// Imported PuTTY configuration.
    PuttyImportOnly,
}

/// A requested port-forwarding rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortForwardSpec {
    /// Local or remote bind endpoint.
    pub source: String,
    /// Target endpoint.
    pub target: String,
}

impl PortForwardSpec {
    /// Creates a new forwarding rule.
    #[must_use]
    pub fn new(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }
}

/// A normalized RusTTY session description.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionConfig {
    /// Human-readable session name.
    pub name: String,
    /// Session protocol.
    pub protocol: Protocol,
    /// Target host if one is required.
    pub host: Option<String>,
    /// Override port if different from the protocol default.
    pub port: Option<u16>,
    /// SSH host-key handling policy.
    pub host_key_policy: HostKeyPolicy,
    /// Storage origin for the session.
    pub saved_in: StorageFormat,
    /// Requested forwarding rules.
    pub port_forwards: Vec<PortForwardSpec>,
}

impl SessionConfig {
    /// Creates a new session with RusTTY defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, protocol: Protocol) -> Self {
        Self {
            name: name.into(),
            protocol,
            host: None,
            port: None,
            host_key_policy: HostKeyPolicy::Ask,
            saved_in: StorageFormat::Rustty,
            port_forwards: Vec::new(),
        }
    }

    /// Sets the target host.
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Sets an explicit port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Adds a port-forwarding rule to the session.
    pub fn add_port_forward(&mut self, source: impl Into<String>, target: impl Into<String>) {
        self.port_forwards
            .push(PortForwardSpec::new(source, target));
    }

    /// Returns the explicit or protocol-default port.
    #[must_use]
    pub fn effective_port(&self) -> Option<u16> {
        self.port.or_else(|| self.protocol.default_port())
    }
}

#[cfg(test)]
mod tests {
    use super::{Protocol, SessionConfig, StorageFormat};

    #[test]
    fn ssh_defaults_to_port_twenty_two() {
        let session = SessionConfig::new("prod", Protocol::Ssh);
        assert_eq!(session.effective_port(), Some(22));
    }

    #[test]
    fn explicit_port_overrides_default() {
        let session = SessionConfig::new("prod", Protocol::Telnet).with_port(2323);
        assert_eq!(session.effective_port(), Some(2323));
    }

    #[test]
    fn new_sessions_default_to_rustty_storage() {
        let session = SessionConfig::new("local", Protocol::Serial);
        assert_eq!(session.saved_in, StorageFormat::Rustty);
    }
}
