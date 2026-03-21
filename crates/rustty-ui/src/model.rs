//! Pure launcher-state logic shared by the RusTTY desktop client.

use std::{
    env,
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
};

use rustty_config::{
    AppConfig, ImportSource, StoredSession, init_config, load_config, load_known_host_keys,
    persist_known_host_key,
};
use rustty_core::{
    HostKeyPolicy, NEXT_RELEASE_NOTES_PATH, PRODUCT_NAME, Protocol, SUITE_CHANGELOG_PATH,
    StorageFormat,
};
use rustty_transport::{
    HostKeyCheck, SshAuthentication, SshExecRequest, VerifiedHostKey, VerifiedHostKeySource,
    execute_ssh_command, host_key_fingerprint, probe_ssh_host_key,
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

/// Progress metadata for a background SSH command run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRunProgress {
    /// Session name or human-readable draft label.
    pub session_name: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Remote command string.
    pub command: String,
}

/// Host-key confirmation details surfaced by the launcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyPrompt {
    /// Session name the prompt belongs to.
    pub session_name: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// SHA-256 fingerprint of the probed key.
    pub fingerprint: String,
    /// Known-hosts path that will receive trust if persisted.
    pub known_hosts_path: PathBuf,
}

/// Result of a completed launcher-side SSH command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRunReport {
    /// Session name the run belongs to.
    pub session_name: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Remote command string.
    pub command: String,
    /// Remote process exit status.
    pub exit_status: u32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Fingerprint of the accepted server host key.
    pub host_key_fingerprint: String,
    /// Why the host key was accepted.
    pub host_key_source: String,
    /// Whether the host key was newly persisted after the run.
    pub persisted_host_key: bool,
    /// Optional warning recorded after a successful run.
    pub warning: Option<String>,
}

/// Launcher-side state for the background SSH command runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRunnerState {
    /// No command activity yet.
    Idle,
    /// The launcher is probing an unknown host key.
    ProbingHostKey(CommandRunProgress),
    /// The launcher is waiting for the operator to trust or reject a host key.
    AwaitingHostKeyConfirmation(HostKeyPrompt),
    /// The launcher is actively running a remote command.
    Running(CommandRunProgress),
    /// The launcher finished a remote command and captured its output.
    Finished(CommandRunReport),
    /// The launcher hit an error before or during command execution.
    Failed(String),
}

#[derive(Debug)]
struct CommandExecutionSpec {
    progress: CommandRunProgress,
    host: String,
    port: u16,
    username: String,
    authentication_methods: Vec<SshAuthentication>,
    known_hosts_path: PathBuf,
}

#[derive(Debug)]
struct PreparedCommandExecution {
    spec: CommandExecutionSpec,
    host_key_check: HostKeyCheck,
    persist_host_key_on_success: bool,
}

#[derive(Debug)]
struct PendingHostKeyExecution {
    spec: CommandExecutionSpec,
    verified_host_key: VerifiedHostKey,
}

enum CommandRunnerEvent {
    AwaitingHostKeyConfirmation {
        pending_execution: Box<PendingHostKeyExecution>,
        prompt: HostKeyPrompt,
    },
    Finished(CommandRunReport),
    Failed(String),
}

/// Pure state backing the RusTTY launcher window.
#[derive(Debug)]
pub struct LauncherModel {
    options: LauncherOptions,
    view: LauncherView,
    filter_text: String,
    selected_session_name: Option<String>,
    quick_connect: QuickConnectDraft,
    status_message: String,
    config_state: ConfigLoadState,
    session_command: String,
    command_runner_state: CommandRunnerState,
    command_runner_receiver: Option<Receiver<CommandRunnerEvent>>,
    pending_host_key_execution: Option<PendingHostKeyExecution>,
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
            session_command: String::new(),
            command_runner_state: CommandRunnerState::Idle,
            command_runner_receiver: None,
            pending_host_key_execution: None,
        };
        model.ensure_selection();
        model.status_message = model.default_status_message();
        model
    }

    /// Returns the current launcher options.
    #[must_use]
    pub fn options(&self) -> &LauncherOptions {
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

    /// Returns the editable remote command for the selected-session runner.
    pub fn session_command_mut(&mut self) -> &mut String {
        &mut self.session_command
    }

    /// Returns the current selected-session remote command.
    #[must_use]
    pub fn session_command(&self) -> &str {
        &self.session_command
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
        if self.selected_session_name.as_deref() == Some(name) {
            return;
        }

        self.selected_session_name = Some(name.to_owned());
        self.session_command.clear();
        if !self.has_active_command_task() {
            self.command_runner_state = CommandRunnerState::Idle;
            self.pending_host_key_execution = None;
            self.command_runner_receiver = None;
        }
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

    /// Starts a background SSH command run for the selected saved session.
    pub fn start_selected_session_command_run(&mut self) -> Result<(), String> {
        if self.has_active_command_task() {
            return Err("A launcher-side SSH command is already running".to_owned());
        }

        let Some(selected_session) = self.selected_session() else {
            return Err("Select a saved SSH session before starting a command".to_owned());
        };
        let command = self.session_command.trim();
        if command.is_empty() {
            return Err("Enter a remote command before starting the runner".to_owned());
        }

        match prepare_command_execution(&selected_session, command, &self.options.known_hosts_path)?
        {
            CommandPreparation::Ready(prepared_execution) => {
                self.status_message = format!(
                    "Starting launcher-side SSH command for '{}'",
                    prepared_execution.spec.progress.session_name
                );
                self.start_command_execution(prepared_execution);
            }
            CommandPreparation::RequiresHostKeyProbe(command_execution_spec) => {
                let progress = command_execution_spec.progress.clone();
                self.command_runner_state = CommandRunnerState::ProbingHostKey(progress.clone());
                self.status_message =
                    format!("Probing server host key for '{}'", progress.session_name);
                self.start_host_key_probe(command_execution_spec);
            }
        }

        Ok(())
    }

    /// Polls background SSH command activity and updates the launcher state.
    pub fn poll_command_runner(&mut self) {
        let Some(receiver) = &self.command_runner_receiver else {
            return;
        };

        match receiver.try_recv() {
            Ok(CommandRunnerEvent::AwaitingHostKeyConfirmation {
                pending_execution,
                prompt,
            }) => {
                self.command_runner_receiver = None;
                self.pending_host_key_execution = Some(*pending_execution);
                self.command_runner_state =
                    CommandRunnerState::AwaitingHostKeyConfirmation(prompt.clone());
                self.status_message = format!("Confirm the host key for '{}'", prompt.session_name);
            }
            Ok(CommandRunnerEvent::Finished(report)) => {
                self.command_runner_receiver = None;
                self.pending_host_key_execution = None;
                self.command_runner_state = CommandRunnerState::Finished(report.clone());
                self.status_message = format!(
                    "Launcher command for '{}' finished with exit status {}",
                    report.session_name, report.exit_status
                );
            }
            Ok(CommandRunnerEvent::Failed(error)) => {
                self.command_runner_receiver = None;
                self.pending_host_key_execution = None;
                self.command_runner_state = CommandRunnerState::Failed(error.clone());
                self.status_message = error;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.command_runner_receiver = None;
                self.pending_host_key_execution = None;
                self.command_runner_state = CommandRunnerState::Failed(
                    "Launcher background task ended unexpectedly".to_owned(),
                );
            }
        }
    }

    /// Returns whether the launcher currently has an active background task.
    #[must_use]
    pub fn has_active_command_task(&self) -> bool {
        self.command_runner_receiver.is_some()
            || matches!(
                self.command_runner_state,
                CommandRunnerState::ProbingHostKey(_) | CommandRunnerState::Running(_)
            )
    }

    /// Returns the current command-runner state.
    #[must_use]
    pub fn command_runner_state(&self) -> &CommandRunnerState {
        &self.command_runner_state
    }

    /// Returns a CLI-oriented preview for the selected-session command runner.
    #[must_use]
    pub fn selected_session_command_preview(&self) -> Option<String> {
        let stored_session = self.selected_session()?;
        Some(session_command_preview(
            &stored_session,
            self.session_command.as_str(),
        ))
    }

    /// Trusts a pending probed host key for a single run.
    pub fn trust_pending_host_key_once(&mut self) -> Result<(), String> {
        self.resume_pending_host_key_execution(false)
    }

    /// Trusts a pending probed host key and persists it after a successful run.
    pub fn trust_pending_host_key_and_save(&mut self) -> Result<(), String> {
        self.resume_pending_host_key_execution(true)
    }

    /// Cancels the current pending host-key confirmation.
    pub fn cancel_pending_host_key(&mut self) {
        if let CommandRunnerState::AwaitingHostKeyConfirmation(prompt) = &self.command_runner_state
        {
            self.status_message = format!(
                "Cancelled host-key confirmation for '{}'",
                prompt.session_name
            );
        }
        self.pending_host_key_execution = None;
        self.command_runner_state = CommandRunnerState::Idle;
    }

    /// Clears the current command-runner result or error.
    pub fn clear_command_runner_state(&mut self) {
        self.pending_host_key_execution = None;
        if !self.has_active_command_task() {
            self.command_runner_state = CommandRunnerState::Idle;
        }
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
            format!("command_runner_state={}", self.command_runner_state_code()),
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

    fn command_runner_state_code(&self) -> &'static str {
        match self.command_runner_state {
            CommandRunnerState::Idle => "idle",
            CommandRunnerState::ProbingHostKey(_) => "probing_host_key",
            CommandRunnerState::AwaitingHostKeyConfirmation(_) => "awaiting_host_key_confirmation",
            CommandRunnerState::Running(_) => "running",
            CommandRunnerState::Finished(_) => "finished",
            CommandRunnerState::Failed(_) => "failed",
        }
    }

    fn resume_pending_host_key_execution(&mut self, persist_host_key: bool) -> Result<(), String> {
        let Some(pending_execution) = self.pending_host_key_execution.take() else {
            return Err("No host-key confirmation is currently pending".to_owned());
        };

        let prepared_execution = PreparedCommandExecution {
            spec: pending_execution.spec,
            host_key_check: HostKeyCheck::RequireMatch(vec![
                pending_execution.verified_host_key.public_key.clone(),
            ]),
            persist_host_key_on_success: persist_host_key,
        };

        self.status_message = if persist_host_key {
            format!(
                "Trusted host key for '{}' and queued persistence after a successful run",
                prepared_execution.spec.progress.session_name
            )
        } else {
            format!(
                "Trusted host key once for '{}'",
                prepared_execution.spec.progress.session_name
            )
        };
        self.start_command_execution(prepared_execution);
        Ok(())
    }

    fn start_host_key_probe(&mut self, command_execution_spec: CommandExecutionSpec) {
        let (sender, receiver) = mpsc::channel();
        let progress = command_execution_spec.progress.clone();
        let known_hosts_path = command_execution_spec.known_hosts_path.clone();
        self.command_runner_receiver = Some(receiver);

        thread::spawn(move || {
            let event = match probe_ssh_host_key(
                command_execution_spec.host.as_str(),
                command_execution_spec.port,
            ) {
                Ok(verified_host_key) => {
                    let fingerprint = host_key_fingerprint(&verified_host_key.public_key);
                    CommandRunnerEvent::AwaitingHostKeyConfirmation {
                        pending_execution: Box::new(PendingHostKeyExecution {
                            spec: command_execution_spec,
                            verified_host_key,
                        }),
                        prompt: HostKeyPrompt {
                            session_name: progress.session_name,
                            host: progress.host,
                            port: progress.port,
                            fingerprint,
                            known_hosts_path,
                        },
                    }
                }
                Err(error) => CommandRunnerEvent::Failed(format!(
                    "Failed to probe the host key for '{}': {error}",
                    progress.session_name
                )),
            };

            let _ = sender.send(event);
        });
    }

    fn start_command_execution(&mut self, prepared_execution: PreparedCommandExecution) {
        let (sender, receiver) = mpsc::channel();
        let progress = prepared_execution.spec.progress.clone();
        self.command_runner_state = CommandRunnerState::Running(progress.clone());
        self.command_runner_receiver = Some(receiver);
        self.pending_host_key_execution = None;

        thread::spawn(move || {
            let request = prepared_execution.build_request();
            let event = match execute_ssh_command(&request) {
                Ok(result) => {
                    let mut warning = None;
                    let persisted_host_key = if prepared_execution.persist_host_key_on_success {
                        match persist_known_host_key(
                            &prepared_execution.spec.known_hosts_path,
                            prepared_execution.spec.host.as_str(),
                            prepared_execution.spec.port,
                            &result.verified_host_key.public_key,
                        ) {
                            Ok(persist_result) => persist_result.changed,
                            Err(error) => {
                                warning = Some(format!(
                                    "Command finished, but saving the trusted host key failed: {error}"
                                ));
                                false
                            }
                        }
                    } else {
                        false
                    };

                    CommandRunnerEvent::Finished(CommandRunReport {
                        session_name: prepared_execution.spec.progress.session_name,
                        host: prepared_execution.spec.host,
                        port: prepared_execution.spec.port,
                        command: prepared_execution.spec.progress.command,
                        exit_status: result.exit_status,
                        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
                        host_key_fingerprint: host_key_fingerprint(
                            &result.verified_host_key.public_key,
                        ),
                        host_key_source: verified_host_key_source_label(
                            result.verified_host_key.source,
                        )
                        .to_owned(),
                        persisted_host_key,
                        warning,
                    })
                }
                Err(error) => CommandRunnerEvent::Failed(format!(
                    "Launcher SSH command for '{}' failed: {error}",
                    progress.session_name
                )),
            };

            let _ = sender.send(event);
        });
    }
}

enum CommandPreparation {
    Ready(PreparedCommandExecution),
    RequiresHostKeyProbe(CommandExecutionSpec),
}

impl PreparedCommandExecution {
    fn build_request(&self) -> SshExecRequest {
        SshExecRequest {
            host: self.spec.host.clone(),
            port: self.spec.port,
            username: self.spec.username.clone(),
            authentication_methods: self.spec.authentication_methods.clone(),
            command: self.spec.progress.command.clone(),
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
            host_key_check: self.host_key_check.clone(),
        }
    }
}

fn prepare_command_execution(
    stored_session: &StoredSession,
    command: &str,
    known_hosts_path: &PathBuf,
) -> Result<CommandPreparation, String> {
    let session = &stored_session.session;
    if session.protocol != Protocol::Ssh {
        return Err(format!(
            "The launcher-side command runner currently supports SSH sessions only; '{}' uses {}",
            session.name,
            session.protocol.label()
        ));
    }

    let host = session
        .host
        .clone()
        .ok_or_else(|| format!("RusTTY session '{}' is missing a host", session.name))?;
    let port = session.effective_port().unwrap_or(22);
    let username = resolve_execution_username(session.username.as_deref())?;
    let authentication_methods = resolve_authentication_methods(session)?;
    let spec = CommandExecutionSpec {
        progress: CommandRunProgress {
            session_name: session.name.clone(),
            host: host.clone(),
            port,
            command: command.trim().to_owned(),
        },
        host: host.clone(),
        port,
        username,
        authentication_methods,
        known_hosts_path: known_hosts_path.clone(),
    };

    let trusted_keys = load_known_host_keys(known_hosts_path, &host, port)
        .map_err(|error| format!("Failed to read RusTTY known-hosts file: {error}"))?
        .into_iter()
        .map(|known_host| known_host.public_key)
        .collect::<Vec<_>>();

    if !trusted_keys.is_empty() {
        return Ok(CommandPreparation::Ready(PreparedCommandExecution {
            spec,
            host_key_check: HostKeyCheck::RequireMatch(trusted_keys),
            persist_host_key_on_success: false,
        }));
    }

    match session.host_key_policy {
        HostKeyPolicy::Strict => Err(format!(
            "Session '{}' requires a trusted host key in {} before the launcher can connect",
            session.name,
            known_hosts_path.display()
        )),
        HostKeyPolicy::AcceptNew => Ok(CommandPreparation::Ready(PreparedCommandExecution {
            spec,
            host_key_check: HostKeyCheck::TrustOnFirstUse,
            persist_host_key_on_success: true,
        })),
        HostKeyPolicy::Ask => Ok(CommandPreparation::RequiresHostKeyProbe(spec)),
    }
}

fn resolve_execution_username(requested_username: Option<&str>) -> Result<String, String> {
    if let Some(requested_username) = requested_username {
        return Ok(requested_username.to_owned());
    }

    env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("USERNAME").ok().filter(|value| !value.is_empty()))
        .ok_or_else(|| {
            "SSH username is required; save it in the RusTTY session or provide USER/USERNAME in the environment"
                .to_owned()
        })
}

fn resolve_authentication_methods(
    session: &rustty_core::SessionConfig,
) -> Result<Vec<SshAuthentication>, String> {
    let private_key_path = session
        .private_key_path
        .as_deref()
        .map(PathBuf::from)
        .map(normalize_private_key_path)
        .transpose()?;
    let key_passphrase = session
        .key_passphrase_env
        .as_deref()
        .map(|env_var| resolve_secret_env(env_var, "SSH key passphrase"))
        .transpose()?;
    let keyboard_interactive_responses = session
        .keyboard_interactive_env
        .as_deref()
        .map(resolve_keyboard_interactive_responses)
        .transpose()?;
    let password = session
        .password_env
        .as_deref()
        .map(|env_var| resolve_secret_env(env_var, "SSH password"))
        .transpose()?;

    let mut authentication_methods = Vec::new();
    if let Some(private_key_path) = private_key_path {
        authentication_methods.push(SshAuthentication::PublicKey {
            private_key_path,
            key_passphrase,
        });
    }

    if let Some(responses) = keyboard_interactive_responses {
        authentication_methods.push(SshAuthentication::KeyboardInteractive { responses });
    }

    if let Some(password) = password {
        authentication_methods.push(SshAuthentication::Password { password });
    }

    if authentication_methods.is_empty() {
        return Err(format!(
            "Session '{}' does not define a launcher-usable SSH auth source yet; save private_key_path, keyboard_interactive_env, or password_env first",
            session.name
        ));
    }

    Ok(authentication_methods)
}

fn resolve_secret_env(env_var: &str, secret_label: &str) -> Result<String, String> {
    let value = env::var(env_var)
        .map_err(|_| format!("{secret_label} environment variable {env_var} is missing"))?;
    if value.is_empty() {
        return Err(format!(
            "{secret_label} environment variable {env_var} must not be empty"
        ));
    }

    Ok(value)
}

fn resolve_keyboard_interactive_responses(env_var: &str) -> Result<Vec<String>, String> {
    let responses = resolve_secret_env(env_var, "SSH keyboard-interactive response")?;
    Ok(responses.lines().map(ToOwned::to_owned).collect())
}

fn normalize_private_key_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("SSH private-key path must not be empty".to_owned());
    }

    let raw_path = path.to_string_lossy();
    if raw_path == "~" {
        return resolve_home_directory();
    }

    if let Some(relative_path) = raw_path
        .strip_prefix("~/")
        .or_else(|| raw_path.strip_prefix("~\\"))
    {
        return Ok(resolve_home_directory()?.join(relative_path));
    }

    Ok(path)
}

fn resolve_home_directory() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            "cannot expand '~' in the SSH private-key path because HOME/USERPROFILE is missing"
                .to_owned()
        })
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

/// Builds a launch preview for a saved-session command invocation.
#[must_use]
pub fn session_command_preview(stored_session: &StoredSession, command: &str) -> String {
    let trimmed_command = command.trim();
    if stored_session.session.protocol != Protocol::Ssh {
        return format!(
            "Launcher-side command execution is currently available for SSH sessions only. '{}' uses {}.",
            stored_session.session.name,
            stored_session.session.protocol.label()
        );
    }

    if trimmed_command.is_empty() {
        return format!(
            "Add a remote command to run '{}' through rusplink.",
            stored_session.session.name
        );
    }

    format!(
        "rusplink --session {} -- {}",
        shell_escape(&stored_session.session.name),
        trimmed_command
            .split_whitespace()
            .map(shell_escape)
            .collect::<Vec<_>>()
            .join(" ")
    )
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

/// Human-readable label for a verified host-key trust source.
#[must_use]
pub const fn verified_host_key_source_label(source: VerifiedHostKeySource) -> &'static str {
    match source {
        VerifiedHostKeySource::UnsafeAcceptAny => "Unsafe accept-any override",
        VerifiedHostKeySource::KnownHosts => "RusTTY known-hosts match",
        VerifiedHostKeySource::TrustOnFirstUse => "Trusted on first use",
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
    } else if value.chars().all(|character| {
        matches!(
            character,
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '/' | ':' | '@'
        )
    }) {
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

    use super::{
        CommandRunnerState, LauncherModel, LauncherOptions, QuickConnectDraft,
        session_command_preview, session_launch_preview,
    };

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

    #[test]
    fn session_command_preview_includes_session_and_command() {
        let stored_session = StoredSession::new(
            SessionConfig::new("prod-ssh", Protocol::Ssh).with_host("prod.example"),
        );

        assert_eq!(
            session_command_preview(&stored_session, "uname -a"),
            "rusplink --session prod-ssh -- uname -a"
        );
    }

    #[test]
    fn command_runner_requires_non_empty_remote_command() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        save_config(&config_path, &AppConfig::sample()).expect("config should save");

        let mut model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        let error = model
            .start_selected_session_command_run()
            .expect_err("empty command should be rejected");

        assert!(error.contains("Enter a remote command"));
        assert_eq!(model.command_runner_state(), &CommandRunnerState::Idle);
    }

    #[test]
    fn command_runner_rejects_non_ssh_saved_sessions_before_runtime_work() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let mut config = AppConfig::empty();
        config.add_session(StoredSession::new(
            SessionConfig::new("legacy", Protocol::Telnet).with_host("bbs.example"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let mut model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        model.session_command_mut().push_str("help");
        let error = model
            .start_selected_session_command_run()
            .expect_err("non-SSH sessions should be rejected");

        assert!(error.contains("supports SSH sessions only"));
        assert_eq!(model.command_runner_state(), &CommandRunnerState::Idle);
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
