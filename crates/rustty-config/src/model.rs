//! Versioned RusTTY configuration model and validation.

use std::collections::BTreeSet;

use rustty_core::{
    PRODUCT_NAME, SessionConfig, StorageFormat, ToolSpec, session::Protocol, tools::ALL_TOOLS,
};
use serde::{Deserialize, Serialize};

use crate::error::ValidationError;

/// The current RusTTY config schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The top-level RusTTY configuration model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppConfig {
    /// Serialized schema version.
    pub schema_version: u32,
    /// Product name for the config file.
    pub product_name: String,
    /// Persisted session data.
    pub session_store: SessionStore,
    /// Tool metadata mirrored into the config for discoverability.
    pub tool_profiles: Vec<ToolProfile>,
}

impl AppConfig {
    /// Builds a sample configuration document for bootstrap review.
    #[must_use]
    pub fn sample() -> Self {
        let sample_session = SessionConfig::new("example-ssh", Protocol::Ssh)
            .with_host("example.com")
            .with_username("ops")
            .with_password_env("RUSTTY_EXAMPLE_SSH_PASSWORD")
            .with_port(22);

        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            product_name: PRODUCT_NAME.to_owned(),
            session_store: SessionStore {
                default_format: StorageFormat::Rustty,
                sessions: vec![StoredSession::new(sample_session)],
            },
            tool_profiles: ALL_TOOLS.into_iter().map(ToolProfile::from).collect(),
        }
    }

    /// Adds a stored session to the configuration.
    pub fn add_session(&mut self, stored_session: StoredSession) {
        self.session_store.sessions.push(stored_session);
    }

    /// Parses a RusTTY config from TOML.
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    /// Renders a RusTTY config as pretty TOML.
    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Returns the number of sessions in the config.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.session_store.sessions.len()
    }

    /// Returns the stored sessions in insertion order.
    #[must_use]
    pub fn sessions(&self) -> &[StoredSession] {
        &self.session_store.sessions
    }

    /// Finds a stored session by name.
    #[must_use]
    pub fn find_session(&self, name: &str) -> Option<&StoredSession> {
        self.session_store
            .sessions
            .iter()
            .find(|stored_session| stored_session.session.name == name)
    }

    /// Returns the number of tool profiles in the config.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tool_profiles.len()
    }

    /// Validates the RusTTY config for repository bootstrap expectations.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }

        if self.product_name.is_empty() {
            return Err(ValidationError::EmptyProductName);
        }

        if self.product_name != PRODUCT_NAME {
            return Err(ValidationError::UnexpectedProductName(
                self.product_name.clone(),
            ));
        }

        let mut seen_session_names = BTreeSet::new();
        for stored_session in &self.session_store.sessions {
            if stored_session.session.name.is_empty() {
                return Err(ValidationError::EmptySessionName);
            }

            if stored_session
                .session
                .username
                .as_deref()
                .is_some_and(str::is_empty)
            {
                return Err(ValidationError::EmptySessionUsername(
                    stored_session.session.name.clone(),
                ));
            }

            if stored_session
                .session
                .password_env
                .as_deref()
                .is_some_and(str::is_empty)
            {
                return Err(ValidationError::EmptySessionPasswordEnv(
                    stored_session.session.name.clone(),
                ));
            }

            let is_new = seen_session_names.insert(stored_session.session.name.clone());
            if !is_new {
                return Err(ValidationError::DuplicateSessionName(
                    stored_session.session.name.clone(),
                ));
            }
        }

        let mut seen_binary_names = BTreeSet::new();
        for tool_profile in &self.tool_profiles {
            let is_new = seen_binary_names.insert(tool_profile.binary_name.clone());
            if !is_new {
                return Err(ValidationError::DuplicateToolBinary(
                    tool_profile.binary_name.clone(),
                ));
            }
        }

        Ok(())
    }
}

/// The persisted RusTTY session store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionStore {
    /// Preferred storage owner.
    pub default_format: StorageFormat,
    /// Known sessions.
    pub sessions: Vec<StoredSession>,
}

/// An individual stored session with import provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredSession {
    /// The normalized session configuration.
    pub session: SessionConfig,
    /// Where the session came from, if it was imported.
    pub imported_from: Option<ImportSource>,
    /// Optional migration or operator notes.
    pub notes: Option<String>,
}

impl StoredSession {
    /// Creates a RusTTY-native stored session.
    #[must_use]
    pub fn new(session: SessionConfig) -> Self {
        Self {
            session,
            imported_from: None,
            notes: None,
        }
    }

    /// Creates an imported stored session.
    #[must_use]
    pub fn imported(session: SessionConfig, imported_from: ImportSource) -> Self {
        Self {
            session,
            imported_from: Some(imported_from),
            notes: None,
        }
    }
}

/// Legacy sources that can feed RusTTY's session store.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    /// Imported from the PuTTY registry layout.
    PuttyRegistry,
    /// Imported from a file-based PuTTY export.
    PuttySessionFile,
    /// Imported from an OpenSSH config source.
    OpenSshConfig,
}

/// Config-visible metadata for a RusTTY tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolProfile {
    /// Binary name for the tool.
    pub binary_name: String,
    /// Manual path for the tool.
    pub manual_path: String,
    /// Changelog path for the tool.
    pub changelog_path: String,
    /// Compatible PuTTY tool names.
    pub replaces: Vec<String>,
}

impl From<ToolSpec> for ToolProfile {
    fn from(tool: ToolSpec) -> Self {
        Self {
            binary_name: tool.binary_name.to_owned(),
            manual_path: tool.doc_path.to_owned(),
            changelog_path: tool.changelog_path.to_owned(),
            replaces: tool
                .replaces
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, ImportSource, StoredSession, ToolProfile};
    use crate::error::ValidationError;
    use rustty_core::{Protocol, SessionConfig};

    #[test]
    fn sample_config_has_expected_counts() {
        let config = AppConfig::sample();
        assert_eq!(config.session_count(), 1);
        assert_eq!(config.tool_count(), 6);
    }

    #[test]
    fn imported_sessions_capture_source() {
        let session = SessionConfig::new("legacy", Protocol::Ssh).with_host("legacy.example");
        let stored = StoredSession::imported(session, ImportSource::PuttyRegistry);
        assert_eq!(stored.imported_from, Some(ImportSource::PuttyRegistry));
    }

    #[test]
    fn sample_config_carries_session_auth_defaults() {
        let config = AppConfig::sample();
        let stored_session = config
            .find_session("example-ssh")
            .expect("sample config should contain the example session");

        assert_eq!(stored_session.session.username.as_deref(), Some("ops"));
        assert_eq!(
            stored_session.session.password_env.as_deref(),
            Some("RUSTTY_EXAMPLE_SSH_PASSWORD")
        );
    }

    #[test]
    fn find_session_returns_matching_entry() {
        let config = AppConfig::sample();
        let stored_session = config
            .find_session("example-ssh")
            .expect("sample config should contain the example session");
        assert_eq!(stored_session.session.protocol, Protocol::Ssh);
    }

    #[test]
    fn validate_rejects_duplicate_session_names() {
        let mut config = AppConfig::sample();
        config.add_session(StoredSession::new(
            SessionConfig::new("example-ssh", Protocol::Telnet).with_host("legacy.example"),
        ));

        assert_eq!(
            config.validate(),
            Err(ValidationError::DuplicateSessionName(
                "example-ssh".to_owned()
            ))
        );
    }

    #[test]
    fn validate_rejects_duplicate_tool_profiles() {
        let mut config = AppConfig::sample();
        config.tool_profiles.push(ToolProfile {
            binary_name: "rustty".to_owned(),
            manual_path: "docs/tools/rustty.adoc".to_owned(),
            changelog_path: "docs/changelogs/rustty.adoc".to_owned(),
            replaces: vec!["putty".to_owned()],
        });

        assert_eq!(
            config.validate(),
            Err(ValidationError::DuplicateToolBinary("rustty".to_owned()))
        );
    }

    #[test]
    fn validate_rejects_empty_session_username() {
        let mut config = AppConfig::sample();
        config.add_session(StoredSession::new(
            SessionConfig::new("broken", Protocol::Ssh)
                .with_host("broken.example")
                .with_username(""),
        ));

        assert_eq!(
            config.validate(),
            Err(ValidationError::EmptySessionUsername("broken".to_owned()))
        );
    }

    #[test]
    fn validate_rejects_empty_password_env() {
        let mut config = AppConfig::sample();
        config.add_session(StoredSession::new(
            SessionConfig::new("broken", Protocol::Ssh)
                .with_host("broken.example")
                .with_password_env(""),
        ));

        assert_eq!(
            config.validate(),
            Err(ValidationError::EmptySessionPasswordEnv(
                "broken".to_owned()
            ))
        );
    }
}
