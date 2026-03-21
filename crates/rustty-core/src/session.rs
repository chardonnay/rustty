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

/// A requested dynamic SOCKS forwarding listener.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicForwardSpec {
    /// Local bind endpoint in `[host]:port` or `host:port` form.
    pub listen: String,
}

impl DynamicForwardSpec {
    /// Creates a new dynamic-forwarding rule.
    #[must_use]
    pub fn new(listen: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
        }
    }
}

/// A requested remote port-forwarding rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteForwardSpec {
    /// Remote bind endpoint.
    pub source: String,
    /// Local target endpoint reached from the RusTTY client.
    pub target: String,
}

impl RemoteForwardSpec {
    /// Creates a new remote-forwarding rule.
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
    /// Preferred username for SSH-family sessions.
    pub username: Option<String>,
    /// Environment variable name that stores the session password.
    pub password_env: Option<String>,
    /// Preferred private-key path for SSH-family sessions.
    pub private_key_path: Option<String>,
    /// Environment variable name that stores the private-key passphrase.
    pub key_passphrase_env: Option<String>,
    /// Environment variable name that stores keyboard-interactive responses.
    pub keyboard_interactive_env: Option<String>,
    /// Override port if different from the protocol default.
    pub port: Option<u16>,
    /// SSH host-key handling policy.
    pub host_key_policy: HostKeyPolicy,
    /// Storage origin for the session.
    pub saved_in: StorageFormat,
    /// Requested forwarding rules.
    #[serde(default)]
    pub port_forwards: Vec<PortForwardSpec>,
    /// Requested remote-forwarding rules.
    #[serde(default)]
    pub remote_forwards: Vec<RemoteForwardSpec>,
    /// Requested dynamic SOCKS forwarding listeners.
    #[serde(default)]
    pub dynamic_forwards: Vec<DynamicForwardSpec>,
}

impl SessionConfig {
    /// Creates a new session with RusTTY defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, protocol: Protocol) -> Self {
        Self {
            name: name.into(),
            protocol,
            host: None,
            username: None,
            password_env: None,
            private_key_path: None,
            key_passphrase_env: None,
            keyboard_interactive_env: None,
            port: None,
            host_key_policy: HostKeyPolicy::Ask,
            saved_in: StorageFormat::Rustty,
            port_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
        }
    }

    /// Sets the target host.
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Sets the preferred username.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the preferred password environment variable name.
    #[must_use]
    pub fn with_password_env(mut self, password_env: impl Into<String>) -> Self {
        self.password_env = Some(password_env.into());
        self
    }

    /// Sets the preferred private-key path.
    #[must_use]
    pub fn with_private_key_path(mut self, private_key_path: impl Into<String>) -> Self {
        self.private_key_path = Some(private_key_path.into());
        self
    }

    /// Sets the preferred private-key passphrase environment variable name.
    #[must_use]
    pub fn with_key_passphrase_env(mut self, key_passphrase_env: impl Into<String>) -> Self {
        self.key_passphrase_env = Some(key_passphrase_env.into());
        self
    }

    /// Sets the preferred keyboard-interactive response environment variable name.
    #[must_use]
    pub fn with_keyboard_interactive_env(
        mut self,
        keyboard_interactive_env: impl Into<String>,
    ) -> Self {
        self.keyboard_interactive_env = Some(keyboard_interactive_env.into());
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

    /// Adds a remote-forwarding rule to the session.
    pub fn add_remote_forward(&mut self, source: impl Into<String>, target: impl Into<String>) {
        self.remote_forwards
            .push(RemoteForwardSpec::new(source, target));
    }

    /// Adds a dynamic-forwarding listener to the session.
    pub fn add_dynamic_forward(&mut self, listen: impl Into<String>) {
        self.dynamic_forwards.push(DynamicForwardSpec::new(listen));
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

    #[test]
    fn session_can_store_username_and_password_env() {
        let session = SessionConfig::new("prod", Protocol::Ssh)
            .with_username("ops")
            .with_password_env("RUSTTY_PROD_PASSWORD");

        assert_eq!(session.username.as_deref(), Some("ops"));
        assert_eq!(
            session.password_env.as_deref(),
            Some("RUSTTY_PROD_PASSWORD")
        );
    }

    #[test]
    fn session_can_store_private_key_defaults() {
        let session = SessionConfig::new("prod", Protocol::Ssh)
            .with_private_key_path("~/.ssh/id_ed25519")
            .with_key_passphrase_env("RUSTTY_PROD_KEY_PASSPHRASE");

        assert_eq!(
            session.private_key_path.as_deref(),
            Some("~/.ssh/id_ed25519")
        );
        assert_eq!(
            session.key_passphrase_env.as_deref(),
            Some("RUSTTY_PROD_KEY_PASSPHRASE")
        );
    }

    #[test]
    fn session_can_store_keyboard_interactive_defaults() {
        let session = SessionConfig::new("prod", Protocol::Ssh)
            .with_keyboard_interactive_env("RUSTTY_PROD_KI_RESPONSES");

        assert_eq!(
            session.keyboard_interactive_env.as_deref(),
            Some("RUSTTY_PROD_KI_RESPONSES")
        );
    }

    #[test]
    fn session_can_store_port_forward_rules() {
        let mut session = SessionConfig::new("prod", Protocol::Ssh);
        session.add_port_forward("127.0.0.1:15432", "db.internal:5432");

        assert_eq!(session.port_forwards.len(), 1);
        assert_eq!(session.port_forwards[0].source, "127.0.0.1:15432");
        assert_eq!(session.port_forwards[0].target, "db.internal:5432");
    }

    #[test]
    fn session_can_store_remote_forward_rules() {
        let mut session = SessionConfig::new("prod", Protocol::Ssh);
        session.add_remote_forward("127.0.0.1:15432", "127.0.0.1:5432");

        assert_eq!(session.remote_forwards.len(), 1);
        assert_eq!(session.remote_forwards[0].source, "127.0.0.1:15432");
        assert_eq!(session.remote_forwards[0].target, "127.0.0.1:5432");
    }

    #[test]
    fn session_can_store_dynamic_forward_rules() {
        let mut session = SessionConfig::new("prod", Protocol::Ssh);
        session.add_dynamic_forward("127.0.0.1:1080");

        assert_eq!(session.dynamic_forwards.len(), 1);
        assert_eq!(session.dynamic_forwards[0].listen, "127.0.0.1:1080");
    }
}
