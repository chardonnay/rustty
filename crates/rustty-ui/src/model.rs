//! Pure launcher-state logic shared by the RusTTY desktop client.

use std::path::PathBuf;

use rustty_config::{AppConfig, ImportSource, StoredSession, init_config, load_config};
use rustty_core::{
    HostKeyPolicy, NEXT_RELEASE_NOTES_PATH, PRODUCT_NAME, Protocol, SUITE_CHANGELOG_PATH,
    StorageFormat,
};

/// The filesystem inputs used to start the RusTTY launcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherOptions {
    /// RusTTY configuration path shown and loaded by the GUI.
    pub config_path: PathBuf,
    /// RusTTY known-hosts path shown by the GUI.
    pub known_hosts_path: PathBuf,
}

impl LauncherOptions {
    /// Builds launcher options from resolved filesystem paths.
    #[must_use]
    pub fn new(config_path: PathBuf, known_hosts_path: PathBuf) -> Self {
        Self {
            config_path,
            known_hosts_path,
        }
    }
}

/// High-level views inside the RusTTY launcher window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherView {
    /// Saved sessions and quick-connect workflow.
    Sessions,
    /// Other RusTTY tools and documentation paths.
    Tools,
    /// Product status and roadmap.
    About,
}

impl LauncherView {
    /// Human-readable tab label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sessions => "Sessions",
            Self::Tools => "Tools",
            Self::About => "About",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfigLoadState {
    Loaded(AppConfig),
    Missing,
    Error(String),
}

/// Quick-connect draft state for the GUI connection form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickConnectDraft {
    /// Optional display name for the draft.
    pub name: String,
    /// Target protocol.
    pub protocol: Protocol,
    /// Target host or serial endpoint.
    pub host: String,
    /// Optional port or service number.
    pub port: String,
    /// Optional username for SSH-family drafts.
    pub username: String,
}

impl Default for QuickConnectDraft {
    fn default() -> Self {
        Self {
            name: "ad-hoc".to_owned(),
            protocol: Protocol::Ssh,
            host: String::new(),
            port: String::new(),
            username: String::new(),
        }
    }
}

impl QuickConnectDraft {
    /// Fills the draft from a stored session so operators can tweak it further.
    pub fn sync_from_session(&mut self, stored_session: &StoredSession) {
        self.name = stored_session.session.name.clone();
        self.protocol = stored_session.session.protocol;
        self.host = stored_session.session.host.clone().unwrap_or_default();
        self.port = stored_session
            .session
            .port
            .map(|value| value.to_string())
            .unwrap_or_default();
        self.username = stored_session.session.username.clone().unwrap_or_default();
    }

    /// Renders a CLI-oriented launch preview for the current draft.
    #[must_use]
    pub fn preview(&self) -> String {
        if self.host.trim().is_empty() {
            return "Enter a host or endpoint to build a launch preview.".to_owned();
        }

        match self.protocol {
            Protocol::Ssh => {
                let mut parts = vec!["rusplink".to_owned()];
                let mut target = String::new();
                if !self.username.trim().is_empty() {
                    target.push_str(self.username.trim());
                    target.push('@');
                }
                target.push_str(self.host.trim());
                parts.push(shell_escape(&target));
                if let Some(port) = normalized_port(&self.port) {
                    parts.push(format!("--port {port}"));
                }
                parts.join(" ")
            }
            Protocol::Scp => format!(
                "ruscp {}",
                shell_escape(&format_target(self.host.trim(), &self.username))
            ),
            Protocol::Sftp => format!(
                "rusftp {}",
                shell_escape(&format_target(self.host.trim(), &self.username))
            ),
            Protocol::Telnet | Protocol::Raw | Protocol::Rlogin | Protocol::Serial => format!(
                "{} GUI transport to {} is planned in the next terminal milestone.",
                self.protocol.label(),
                self.host.trim()
            ),
            Protocol::Agent | Protocol::Keygen => {
                "This draft protocol is handled by another RusTTY tool.".to_owned()
            }
        }
    }
}

/// Pure state backing the RusTTY launcher window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherModel {
    options: LauncherOptions,
    view: LauncherView,
    filter_text: String,
    selected_session_name: Option<String>,
    quick_connect: QuickConnectDraft,
    status_message: String,
    config_state: ConfigLoadState,
}

impl LauncherModel {
    /// Loads launcher state from the configured RusTTY paths.
    #[must_use]
    pub fn load(options: LauncherOptions) -> Self {
        let config_state = read_config_state(&options.config_path);
        let mut model = Self {
            options,
            view: LauncherView::Sessions,
            filter_text: String::new(),
            selected_session_name: None,
            quick_connect: QuickConnectDraft::default(),
            status_message: String::new(),
            config_state,
        };
        model.ensure_selection();
        model.status_message = model.default_status_message();
        model
    }

    /// Returns the current launcher options.
    #[must_use]
    pub const fn options(&self) -> &LauncherOptions {
        &self.options
    }

    /// Returns the selected high-level window view.
    #[must_use]
    pub const fn view(&self) -> LauncherView {
        self.view
    }

    /// Selects the current high-level window view.
    pub fn set_view(&mut self, view: LauncherView) {
        self.view = view;
    }

    /// Returns the session filter text.
    #[must_use]
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Returns mutable access to the session filter text.
    pub fn filter_text_mut(&mut self) -> &mut String {
        &mut self.filter_text
    }

    /// Returns mutable access to the quick-connect draft.
    pub fn quick_connect_mut(&mut self) -> &mut QuickConnectDraft {
        &mut self.quick_connect
    }

    /// Returns the current quick-connect draft.
    #[must_use]
    pub const fn quick_connect(&self) -> &QuickConnectDraft {
        &self.quick_connect
    }

    /// Returns the current status message shown in the GUI footer.
    #[must_use]
    pub fn status_message(&self) -> &str {
        &self.status_message
    }

    /// Replaces the status message shown in the GUI footer.
    pub fn set_status_message(&mut self, status_message: impl Into<String>) {
        self.status_message = status_message.into();
    }

    /// Reloads the RusTTY config from disk.
    pub fn reload(&mut self) {
        self.config_state = read_config_state(&self.options.config_path);
        self.ensure_selection();
        self.status_message = self.default_status_message();
    }

    /// Ensures the sample config exists and then reloads it.
    pub fn initialize_sample_config(&mut self) -> Result<(), String> {
        let result = init_config(&self.options.config_path).map_err(|error| error.to_string())?;
        self.reload();
        self.status_message = if result.created {
            format!("Created sample config at {}", result.path.display())
        } else {
            format!(
                "Config already existed and validated at {}",
                result.path.display()
            )
        };
        Ok(())
    }

    /// Returns whether the config exists and loaded successfully.
    #[must_use]
    pub fn has_loaded_config(&self) -> bool {
        matches!(self.config_state, ConfigLoadState::Loaded(_))
    }

    /// Returns whether the config path is currently missing.
    #[must_use]
    pub fn config_is_missing(&self) -> bool {
        matches!(self.config_state, ConfigLoadState::Missing)
    }

    /// Returns the current config error, if loading failed.
    #[must_use]
    pub fn config_error(&self) -> Option<&str> {
        match &self.config_state {
            ConfigLoadState::Error(message) => Some(message.as_str()),
            ConfigLoadState::Loaded(_) | ConfigLoadState::Missing => None,
        }
    }

    /// Returns the config summary shown throughout the GUI.
    #[must_use]
    pub fn config_summary(&self) -> String {
        match &self.config_state {
            ConfigLoadState::Loaded(config) => format!(
                "Loaded {} session(s) from {}",
                config.session_count(),
                self.options.config_path.display()
            ),
            ConfigLoadState::Missing => format!(
                "No config found at {}. Create one from the launcher or with `rustty --init-config`.",
                self.options.config_path.display()
            ),
            ConfigLoadState::Error(message) => format!(
                "Failed to load {}: {message}",
                self.options.config_path.display()
            ),
        }
    }

    /// Returns the total number of saved sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.config().map_or(0, AppConfig::session_count)
    }

    /// Returns the number of imported sessions.
    #[must_use]
    pub fn imported_session_count(&self) -> usize {
        self.config().map_or(0, |config| {
            config
                .sessions()
                .iter()
                .filter(|stored_session| stored_session.imported_from.is_some())
                .count()
        })
    }

    /// Returns the number of sessions using the requested protocol.
    #[must_use]
    pub fn protocol_count(&self, protocol: Protocol) -> usize {
        self.config().map_or(0, |config| {
            config
                .sessions()
                .iter()
                .filter(|stored_session| stored_session.session.protocol == protocol)
                .count()
        })
    }

    /// Returns cloned filtered sessions for GUI rendering.
    #[must_use]
    pub fn filtered_sessions(&self) -> Vec<StoredSession> {
        let Some(config) = self.config() else {
            return Vec::new();
        };

        let filter = normalized_filter(&self.filter_text);
        config
            .sessions()
            .iter()
            .filter(|stored_session| session_matches_filter(stored_session, &filter))
            .cloned()
            .collect()
    }

    /// Returns the cloned currently selected session, if any.
    #[must_use]
    pub fn selected_session(&self) -> Option<StoredSession> {
        let selected_name = self.selected_session_name.as_deref()?;
        self.config()?.find_session(selected_name).cloned()
    }

    /// Selects a saved session by name.
    pub fn select_session(&mut self, name: &str) {
        self.selected_session_name = Some(name.to_owned());
    }

    /// Copies the selected session details into the quick-connect draft.
    pub fn populate_draft_from_selected_session(&mut self) -> bool {
        let Some(selected_session) = self.selected_session() else {
            return false;
        };
        self.quick_connect.sync_from_session(&selected_session);
        self.status_message = format!(
            "Loaded session '{}' into the quick-connect draft",
            selected_session.session.name
        );
        true
    }

    /// Returns diagnostic lines for the footer panel.
    #[must_use]
    pub fn diagnostics_lines(&self) -> Vec<String> {
        let selected_session = self
            .selected_session_name
            .clone()
            .unwrap_or_else(|| "none".to_owned());
        vec![
            format!("product={PRODUCT_NAME}"),
            format!("config_path={}", self.options.config_path.display()),
            format!(
                "known_hosts_path={}",
                self.options.known_hosts_path.display()
            ),
            format!("config_status={}", self.config_status_code()),
            format!("selected_session={selected_session}"),
            format!("saved_sessions={}", self.session_count()),
            format!("imported_sessions={}", self.imported_session_count()),
            format!("suite_changelog={SUITE_CHANGELOG_PATH}"),
            format!("release_notes={NEXT_RELEASE_NOTES_PATH}"),
        ]
    }

    fn config(&self) -> Option<&AppConfig> {
        match &self.config_state {
            ConfigLoadState::Loaded(config) => Some(config),
            ConfigLoadState::Missing | ConfigLoadState::Error(_) => None,
        }
    }

    fn ensure_selection(&mut self) {
        let Some(config) = self.config() else {
            self.selected_session_name = None;
            return;
        };

        if self
            .selected_session_name
            .as_deref()
            .is_some_and(|name| config.find_session(name).is_some())
        {
            return;
        }

        self.selected_session_name = config
            .sessions()
            .first()
            .map(|stored_session| stored_session.session.name.clone());
    }

    fn default_status_message(&self) -> String {
        match &self.config_state {
            ConfigLoadState::Loaded(config) => format!(
                "Launcher ready with {} saved session(s) and {} imported session(s)",
                config.session_count(),
                self.imported_session_count()
            ),
            ConfigLoadState::Missing => {
                "Launcher ready. No RusTTY config exists yet, so the session list is empty."
                    .to_owned()
            }
            ConfigLoadState::Error(_) => {
                "Launcher opened with a config error. Review diagnostics before editing.".to_owned()
            }
        }
    }

    fn config_status_code(&self) -> &'static str {
        match self.config_state {
            ConfigLoadState::Loaded(_) => "loaded",
            ConfigLoadState::Missing => "missing",
            ConfigLoadState::Error(_) => "error",
        }
    }
}

/// Builds a launch preview for a saved session.
#[must_use]
pub fn session_launch_preview(stored_session: &StoredSession) -> String {
    let session = &stored_session.session;
    match session.protocol {
        Protocol::Ssh => format!("rusplink --session {}", shell_escape(&session.name)),
        Protocol::Scp => format!("ruscp --session {}", shell_escape(&session.name)),
        Protocol::Sftp => format!("rusftp --session {}", shell_escape(&session.name)),
        Protocol::Telnet | Protocol::Raw | Protocol::Rlogin | Protocol::Serial => format!(
            "{} support is modeled in RusTTY config, but the embedded GUI transport window is still pending for session '{}'.",
            session.protocol.label(),
            session.name
        ),
        Protocol::Agent | Protocol::Keygen => {
            "This saved session belongs to a non-terminal tool.".to_owned()
        }
    }
}

/// Human-readable label for a config import source.
#[must_use]
pub const fn import_source_label(import_source: ImportSource) -> &'static str {
    match import_source {
        ImportSource::PuttyRegistry => "PuTTY registry export",
        ImportSource::PuttySessionFile => "PuTTY session file",
        ImportSource::OpenSshConfig => "OpenSSH config",
    }
}

/// Human-readable label for a session storage format.
#[must_use]
pub const fn storage_format_label(storage_format: StorageFormat) -> &'static str {
    match storage_format {
        StorageFormat::Rustty => "RusTTY native",
        StorageFormat::PuttyImportOnly => "PuTTY import",
    }
}

/// Human-readable label for an SSH host-key policy.
#[must_use]
pub const fn host_key_policy_label(host_key_policy: HostKeyPolicy) -> &'static str {
    match host_key_policy {
        HostKeyPolicy::Ask => "Ask",
        HostKeyPolicy::Strict => "Strict",
        HostKeyPolicy::AcceptNew => "Accept new",
    }
}

fn read_config_state(config_path: &PathBuf) -> ConfigLoadState {
    if !config_path.exists() {
        return ConfigLoadState::Missing;
    }

    match load_config(config_path) {
        Ok(config) => ConfigLoadState::Loaded(config),
        Err(error) => ConfigLoadState::Error(error.to_string()),
    }
}

fn normalized_filter(filter_text: &str) -> String {
    filter_text.trim().to_ascii_lowercase()
}

fn session_matches_filter(stored_session: &StoredSession, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    let session = &stored_session.session;
    session.name.to_ascii_lowercase().contains(filter)
        || session
            .protocol
            .label()
            .to_ascii_lowercase()
            .contains(filter)
        || session
            .host
            .as_deref()
            .is_some_and(|host| host.to_ascii_lowercase().contains(filter))
        || session
            .username
            .as_deref()
            .is_some_and(|username| username.to_ascii_lowercase().contains(filter))
        || stored_session
            .notes
            .as_deref()
            .is_some_and(|notes| notes.to_ascii_lowercase().contains(filter))
}

fn normalized_port(port: &str) -> Option<&str> {
    let trimmed = port.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn format_target(host: &str, username: &str) -> String {
    if username.trim().is_empty() {
        host.to_owned()
    } else {
        format!("{}@{}", username.trim(), host)
    }
}

fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        "''".to_owned()
    } else if value
        .chars()
        .all(|character| matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '/' | ':' | '@'))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rustty_config::{AppConfig, StoredSession, save_config};
    use rustty_core::{Protocol, SessionConfig};

    use super::{LauncherModel, LauncherOptions, QuickConnectDraft, session_launch_preview};

    #[test]
    fn missing_config_starts_with_empty_session_list() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("missing.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));

        assert_eq!(model.session_count(), 0);
        assert!(model.config_is_missing());
        assert!(model.selected_session().is_none());
    }

    #[test]
    fn loading_config_selects_first_session() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let mut config = AppConfig::empty();
        config.add_session(StoredSession::new(
            SessionConfig::new("prod-ssh", Protocol::Ssh)
                .with_host("prod.example")
                .with_username("ops"),
        ));
        config.add_session(StoredSession::new(
            SessionConfig::new("lab-serial", Protocol::Serial).with_host("/dev/tty.usbmodem1"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        let selected_session = model
            .selected_session()
            .expect("first saved session should be selected");

        assert_eq!(selected_session.session.name, "prod-ssh");
        assert_eq!(model.session_count(), 2);
    }

    #[test]
    fn quick_connect_preview_prefers_rusplink_for_ssh() {
        let draft = QuickConnectDraft {
            name: "prod".to_owned(),
            protocol: Protocol::Ssh,
            host: "prod.example".to_owned(),
            port: "2222".to_owned(),
            username: "ops".to_owned(),
        };

        assert_eq!(draft.preview(), "rusplink ops@prod.example --port 2222");
    }

    #[test]
    fn session_launch_preview_marks_pending_terminal_backends() {
        let stored_session = StoredSession::new(
            SessionConfig::new("legacy", Protocol::Telnet).with_host("bbs.example"),
        );

        let preview = session_launch_preview(&stored_session);
        assert!(preview.contains("embedded GUI transport window is still pending"));
        assert!(preview.contains("legacy"));
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustty-ui-model-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
