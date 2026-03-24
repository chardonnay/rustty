//! Pure launcher-state logic shared by the RusTTY desktop client.

use std::{
    env,
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
};

use rustty_config::{
    AppConfig, ImportPuttySessionsResult, ImportSource, StoredSession, import_putty_sessions,
    init_config, load_config, load_known_host_keys, persist_known_host_key, save_config,
};
use rustty_core::{
    DynamicForwardSpec, HostKeyPolicy, NEXT_RELEASE_NOTES_PATH, PRODUCT_NAME, PortForwardSpec,
    Protocol, RemoteForwardSpec, SUITE_CHANGELOG_PATH, SessionConfig, StorageFormat,
};
use rustty_transport::{
    HostKeyCheck, InteractiveShellEvent, InteractiveShellSession, SshAuthentication,
    SshExecRequest, SshShellRequest, TerminalSize, VerifiedHostKey, VerifiedHostKeySource,
    execute_ssh_command, host_key_fingerprint, probe_ssh_host_key, start_interactive_shell_session,
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

/// Editable GUI-side session draft that can be saved into the RusTTY config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionEditorDraft {
    /// Original session name if this draft edits an existing saved session.
    pub source_session_name: Option<String>,
    /// Optional import provenance shown for migrated sessions.
    pub imported_from: Option<ImportSource>,
    /// Human-readable session name.
    pub name: String,
    /// Session protocol.
    pub protocol: Protocol,
    /// Target host, endpoint, or serial device.
    pub host: String,
    /// Optional port override.
    pub port: String,
    /// Preferred username.
    pub username: String,
    /// SSH host-key handling policy.
    pub host_key_policy: HostKeyPolicy,
    /// Password environment variable name.
    pub password_env: String,
    /// Private-key path.
    pub private_key_path: String,
    /// Private-key passphrase environment variable name.
    pub key_passphrase_env: String,
    /// Keyboard-interactive response environment variable name.
    pub keyboard_interactive_env: String,
    /// Local forwarding rules in `source -> target` form.
    pub local_forwards: String,
    /// Remote forwarding rules in `source -> target` form.
    pub remote_forwards: String,
    /// Dynamic forwarding listeners, one per line.
    pub dynamic_forwards: String,
    /// Optional operator or migration notes.
    pub notes: String,
}

impl Default for SessionEditorDraft {
    fn default() -> Self {
        Self {
            source_session_name: None,
            imported_from: None,
            name: String::new(),
            protocol: Protocol::Ssh,
            host: String::new(),
            port: String::new(),
            username: String::new(),
            host_key_policy: HostKeyPolicy::Ask,
            password_env: String::new(),
            private_key_path: String::new(),
            key_passphrase_env: String::new(),
            keyboard_interactive_env: String::new(),
            local_forwards: String::new(),
            remote_forwards: String::new(),
            dynamic_forwards: String::new(),
            notes: String::new(),
        }
    }
}

impl SessionEditorDraft {
    /// Builds an editable draft from a persisted session.
    #[must_use]
    pub fn from_stored_session(stored_session: &StoredSession) -> Self {
        let session = &stored_session.session;
        Self {
            source_session_name: Some(session.name.clone()),
            imported_from: stored_session.imported_from,
            name: session.name.clone(),
            protocol: session.protocol,
            host: session.host.clone().unwrap_or_default(),
            port: session
                .port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            username: session.username.clone().unwrap_or_default(),
            host_key_policy: session.host_key_policy,
            password_env: session.password_env.clone().unwrap_or_default(),
            private_key_path: session.private_key_path.clone().unwrap_or_default(),
            key_passphrase_env: session.key_passphrase_env.clone().unwrap_or_default(),
            keyboard_interactive_env: session.keyboard_interactive_env.clone().unwrap_or_default(),
            local_forwards: render_forward_lines(&session.port_forwards),
            remote_forwards: render_remote_forward_lines(&session.remote_forwards),
            dynamic_forwards: render_dynamic_forward_lines(&session.dynamic_forwards),
            notes: stored_session.notes.clone().unwrap_or_default(),
        }
    }

    /// Returns whether this draft edits an existing saved session.
    #[must_use]
    pub fn is_editing_existing_session(&self) -> bool {
        self.source_session_name.is_some()
    }

    /// Builds a CLI-oriented launch preview for the current draft.
    #[must_use]
    pub fn preview(&self) -> String {
        let session_name = if self.name.trim().is_empty() {
            "<unnamed-session>"
        } else {
            self.name.trim()
        };

        match self.protocol {
            Protocol::Ssh => format!("rusplink --session {}", shell_escape(session_name)),
            Protocol::Scp => format!("ruscp --session {}", shell_escape(session_name)),
            Protocol::Sftp => format!("rusftp --session {}", shell_escape(session_name)),
            Protocol::Telnet | Protocol::Raw | Protocol::Rlogin | Protocol::Serial => format!(
                "{} session '{}' is saved in RusTTY config, but the embedded GUI transport window is still pending for this protocol.",
                self.protocol.label(),
                session_name
            ),
            Protocol::Agent | Protocol::Keygen => {
                "This draft belongs to a non-terminal RusTTY tool.".to_owned()
            }
        }
    }

    fn to_stored_session(&self) -> Result<StoredSession, String> {
        let session_name = self.name.trim();
        if session_name.is_empty() {
            return Err("Saved session names must not be empty".to_owned());
        }

        let mut session = SessionConfig::new(session_name, self.protocol);
        session.host = normalized_optional_string(&self.host);
        session.username = normalized_optional_string(&self.username);
        session.password_env = normalized_optional_string(&self.password_env);
        session.private_key_path = normalized_optional_string(&self.private_key_path);
        session.key_passphrase_env = normalized_optional_string(&self.key_passphrase_env);
        session.keyboard_interactive_env =
            normalized_optional_string(&self.keyboard_interactive_env);
        session.port = parse_optional_port(&self.port)?;
        session.host_key_policy = self.host_key_policy;
        session.port_forwards = parse_forward_lines(
            session_name,
            self.local_forwards.as_str(),
            PortForwardSpec::new,
        )?;
        session.remote_forwards = parse_forward_lines(
            session_name,
            self.remote_forwards.as_str(),
            RemoteForwardSpec::new,
        )?;
        session.dynamic_forwards = parse_dynamic_forward_lines(self.dynamic_forwards.as_str());

        Ok(StoredSession {
            session,
            imported_from: self.imported_from,
            notes: normalized_optional_string(&self.notes),
        })
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

/// Progress metadata for a live interactive SSH shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellRunProgress {
    /// Session name or human-readable draft label.
    pub session_name: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Requested terminal type.
    pub term_type: String,
    /// Current PTY size tracked by the GUI.
    pub terminal_size: TerminalSize,
}

/// Result of a completed interactive SSH shell session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellRunReport {
    /// Session name the shell belongs to.
    pub session_name: String,
    /// Remote host.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Remote shell exit status.
    pub exit_status: u32,
    /// Fingerprint of the accepted server host key.
    pub host_key_fingerprint: String,
    /// Why the host key was accepted.
    pub host_key_source: String,
    /// Whether the host key was newly persisted after connect.
    pub persisted_host_key: bool,
}

/// Live state for the GUI-driven interactive shell session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InteractiveShellState {
    /// No interactive shell work is active.
    Idle,
    /// The launcher is probing an unknown host key before opening a shell.
    ProbingHostKey(ShellRunProgress),
    /// The launcher is waiting for the operator to confirm a host key.
    AwaitingHostKeyConfirmation(HostKeyPrompt),
    /// The GUI shell session is connecting but not yet streaming.
    Connecting(ShellRunProgress),
    /// The GUI shell session is active.
    Running(ShellRunProgress),
    /// The GUI shell session exited normally.
    Finished(ShellRunReport),
    /// The GUI shell session failed.
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

#[derive(Debug)]
struct ShellExecutionSpec {
    progress: ShellRunProgress,
    host: String,
    port: u16,
    username: String,
    authentication_methods: Vec<SshAuthentication>,
    known_hosts_path: PathBuf,
}

#[derive(Debug)]
struct PreparedShellExecution {
    spec: ShellExecutionSpec,
    host_key_check: HostKeyCheck,
    persist_host_key_on_connect: bool,
}

#[derive(Debug)]
struct PendingShellExecution {
    spec: ShellExecutionSpec,
    verified_host_key: VerifiedHostKey,
}

enum ShellHostKeyProbeEvent {
    AwaitingHostKeyConfirmation {
        pending_execution: Box<PendingShellExecution>,
        prompt: HostKeyPrompt,
    },
    Failed(String),
}

enum CommandRunnerEvent {
    AwaitingHostKeyConfirmation {
        pending_execution: Box<PendingHostKeyExecution>,
        prompt: HostKeyPrompt,
    },
    Finished(CommandRunReport),
    Failed(String),
}

/// Visual tone for a transcript entry inside the first RusTTY terminal window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalTranscriptTone {
    /// A command prompt or operator action.
    Prompt,
    /// Neutral informational output.
    Info,
    /// Successful completion or positive status.
    Success,
    /// A warning that still leaves the window usable.
    Warning,
    /// An execution or validation error.
    Error,
    /// Captured standard output.
    Stdout,
    /// Captured standard error.
    Stderr,
}

/// A rendered transcript item for the first GUI-side terminal window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalTranscriptEntry {
    /// Visual tone for the entry.
    pub tone: TerminalTranscriptTone,
    /// Short heading shown above the transcript body.
    pub title: String,
    /// Multiline body content rendered in a terminal-style surface.
    pub body: String,
}

/// Snapshot of the current terminal-window state for egui rendering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalWindowSnapshot {
    /// Saved session name currently bound to the window.
    pub session_name: String,
    /// Saved session protocol.
    pub protocol: Protocol,
    /// Human-readable endpoint summary.
    pub endpoint: String,
    /// Whether the terminal window should currently be visible.
    pub visible: bool,
    /// Editable remote command text shown in the window.
    pub command_input: String,
    /// CLI-oriented launch preview for the bound session.
    pub launch_preview: String,
    /// CLI-oriented preview for the current remote command.
    pub command_preview: String,
    /// Transcript entries captured in the window.
    pub transcript: Vec<TerminalTranscriptEntry>,
    /// Current background command-runner state for the window.
    pub command_runner_state: CommandRunnerState,
    /// Current interactive-shell state for the window.
    pub shell_state: InteractiveShellState,
    /// Current rendered live terminal buffer.
    pub shell_screen: String,
}

#[derive(Debug)]
struct TerminalWindowState {
    session_name: String,
    protocol: Protocol,
    endpoint: String,
    visible: bool,
    command_input: String,
    transcript: Vec<TerminalTranscriptEntry>,
    command_runner_state: CommandRunnerState,
    command_runner_receiver: Option<Receiver<CommandRunnerEvent>>,
    pending_host_key_execution: Option<PendingHostKeyExecution>,
    shell_state: InteractiveShellState,
    shell_screen: String,
    shell_session: Option<InteractiveShellSession>,
    shell_probe_receiver: Option<Receiver<ShellHostKeyProbeEvent>>,
    pending_shell_execution: Option<PendingShellExecution>,
    shell_verified_host_key: Option<VerifiedHostKey>,
    persist_shell_host_key_on_connect: bool,
    shell_persisted_host_key: bool,
}

impl TerminalWindowState {
    fn new(stored_session: &StoredSession) -> Self {
        let session = &stored_session.session;
        let mut state = Self {
            session_name: session.name.clone(),
            protocol: session.protocol,
            endpoint: session_endpoint_summary(stored_session),
            visible: true,
            command_input: String::new(),
            transcript: Vec::new(),
            command_runner_state: CommandRunnerState::Idle,
            command_runner_receiver: None,
            pending_host_key_execution: None,
            shell_state: InteractiveShellState::Idle,
            shell_screen: String::new(),
            shell_session: None,
            shell_probe_receiver: None,
            pending_shell_execution: None,
            shell_verified_host_key: None,
            persist_shell_host_key_on_connect: false,
            shell_persisted_host_key: false,
        };

        state.push_transcript(
            TerminalTranscriptTone::Info,
            "Session workspace ready",
            format!(
                "Opened a dedicated RusTTY session window for '{}'. This window keeps saved-session command history, host-key decisions, and live shell state separate from the launcher.",
                session.name
            ),
        );

        state
    }

    fn snapshot(&self, launch_preview: String, command_preview: String) -> TerminalWindowSnapshot {
        TerminalWindowSnapshot {
            session_name: self.session_name.clone(),
            protocol: self.protocol,
            endpoint: self.endpoint.clone(),
            visible: self.visible,
            command_input: self.command_input.clone(),
            launch_preview,
            command_preview,
            transcript: self.transcript.clone(),
            command_runner_state: self.command_runner_state.clone(),
            shell_state: self.shell_state.clone(),
            shell_screen: self.shell_screen.clone(),
        }
    }

    fn has_active_command_task(&self) -> bool {
        self.command_runner_receiver.is_some()
            || matches!(
                self.command_runner_state,
                CommandRunnerState::ProbingHostKey(_) | CommandRunnerState::Running(_)
            )
    }

    fn has_active_shell_task(&self) -> bool {
        self.shell_session.is_some()
            || self.shell_probe_receiver.is_some()
            || matches!(
                self.shell_state,
                InteractiveShellState::ProbingHostKey(_)
                    | InteractiveShellState::Connecting(_)
                    | InteractiveShellState::Running(_)
            )
    }

    fn has_active_task(&self) -> bool {
        self.has_active_command_task() || self.has_active_shell_task()
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

    fn shell_state_code(&self) -> &'static str {
        match self.shell_state {
            InteractiveShellState::Idle => "idle",
            InteractiveShellState::ProbingHostKey(_) => "probing_host_key",
            InteractiveShellState::AwaitingHostKeyConfirmation(_) => {
                "awaiting_host_key_confirmation"
            }
            InteractiveShellState::Connecting(_) => "connecting",
            InteractiveShellState::Running(_) => "running",
            InteractiveShellState::Finished(_) => "finished",
            InteractiveShellState::Failed(_) => "failed",
        }
    }

    fn push_transcript(
        &mut self,
        tone: TerminalTranscriptTone,
        title: impl Into<String>,
        body: impl Into<String>,
    ) {
        self.transcript.push(TerminalTranscriptEntry {
            tone,
            title: title.into(),
            body: body.into(),
        });
    }
}

/// Pure state backing the RusTTY launcher window.
#[derive(Debug)]
pub struct LauncherModel {
    options: LauncherOptions,
    view: LauncherView,
    filter_text: String,
    selected_session_name: Option<String>,
    quick_connect: QuickConnectDraft,
    session_editor: SessionEditorDraft,
    putty_import_path: String,
    putty_import_report: Option<String>,
    status_message: String,
    config_state: ConfigLoadState,
    terminal_window: Option<TerminalWindowState>,
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
            session_editor: SessionEditorDraft::default(),
            putty_import_path: String::new(),
            putty_import_report: None,
            status_message: String::new(),
            config_state,
            terminal_window: None,
        };
        model.ensure_selection();
        model.sync_session_editor_from_selection();
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

    /// Returns the current editable session draft.
    #[must_use]
    pub const fn session_editor(&self) -> &SessionEditorDraft {
        &self.session_editor
    }

    /// Returns mutable access to the editable session draft.
    pub fn session_editor_mut(&mut self) -> &mut SessionEditorDraft {
        &mut self.session_editor
    }

    /// Starts a fresh saved-session draft.
    pub fn start_new_session_draft(&mut self) {
        self.selected_session_name = None;
        self.session_editor = SessionEditorDraft::default();
        self.status_message =
            "Editing a new RusTTY session draft. Save it to write a real session to config."
                .to_owned();
    }

    /// Reloads the editor from the currently selected saved session.
    pub fn load_editor_from_selected_session(&mut self) -> Result<(), String> {
        let selected_session = self
            .selected_session()
            .ok_or_else(|| "Select a saved session before reloading the editor".to_owned())?;
        self.session_editor = SessionEditorDraft::from_stored_session(&selected_session);
        self.status_message = format!(
            "Loaded session '{}' into the editor",
            selected_session.session.name
        );
        Ok(())
    }

    /// Returns the current PuTTY import source path draft.
    #[must_use]
    pub fn putty_import_path(&self) -> &str {
        &self.putty_import_path
    }

    /// Returns mutable access to the PuTTY import source path draft.
    pub fn putty_import_path_mut(&mut self) -> &mut String {
        &mut self.putty_import_path
    }

    /// Returns the most recent PuTTY import report.
    #[must_use]
    pub fn putty_import_report(&self) -> Option<&str> {
        self.putty_import_report.as_deref()
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
        self.sync_session_editor_from_selection();
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

    /// Saves the current session-editor draft to the RusTTY config file.
    pub fn save_session_editor(&mut self) -> Result<(), String> {
        let stored_session = self.session_editor.to_stored_session()?;
        let original_name = self.session_editor.source_session_name.clone();

        if let Some(terminal_window) = &self.terminal_window {
            let edits_current_terminal = original_name
                .as_deref()
                .is_some_and(|name| name == terminal_window.session_name)
                || terminal_window.session_name == stored_session.session.name;
            if edits_current_terminal && terminal_window.has_active_task() {
                return Err(format!(
                    "Wait for the terminal activity in '{}' to finish before changing or renaming that session",
                    terminal_window.session_name
                ));
            }
        }

        let mut config = self.editable_config()?;
        let existing_index = original_name.as_deref().and_then(|name| {
            config
                .session_store
                .sessions
                .iter()
                .position(|candidate| candidate.session.name == name)
        });

        match existing_index {
            Some(index) => config.session_store.sessions[index] = stored_session.clone(),
            None => config.session_store.sessions.push(stored_session.clone()),
        }

        save_config(&self.options.config_path, &config).map_err(|error| error.to_string())?;
        self.config_state = ConfigLoadState::Loaded(config);
        self.selected_session_name = Some(stored_session.session.name.clone());
        self.session_editor = SessionEditorDraft::from_stored_session(&stored_session);
        self.refresh_terminal_window_binding(original_name.as_deref(), &stored_session);
        self.ensure_selection();
        self.status_message = format!(
            "Saved session '{}' to {}",
            stored_session.session.name,
            self.options.config_path.display()
        );
        Ok(())
    }

    /// Deletes the currently selected saved session from the RusTTY config.
    pub fn delete_selected_session(&mut self) -> Result<(), String> {
        let selected_session = self
            .selected_session()
            .ok_or_else(|| "Select a saved session before deleting it".to_owned())?;

        if let Some(terminal_window) = &self.terminal_window {
            if terminal_window.session_name == selected_session.session.name
                && terminal_window.has_active_task()
            {
                return Err(format!(
                    "Wait for the terminal activity in '{}' to finish before deleting that session",
                    terminal_window.session_name
                ));
            }
        }

        let mut config = self.editable_config()?;
        let Some(index) = config
            .session_store
            .sessions
            .iter()
            .position(|candidate| candidate.session.name == selected_session.session.name)
        else {
            return Err(format!(
                "Session '{}' is no longer present in the current config",
                selected_session.session.name
            ));
        };

        config.session_store.sessions.remove(index);
        save_config(&self.options.config_path, &config).map_err(|error| error.to_string())?;
        self.config_state = ConfigLoadState::Loaded(config);
        self.selected_session_name = None;
        if self
            .terminal_window
            .as_ref()
            .is_some_and(|terminal_window| {
                terminal_window.session_name == selected_session.session.name
            })
        {
            self.terminal_window = None;
        }
        self.ensure_selection();
        self.sync_session_editor_from_selection();
        self.status_message = format!(
            "Deleted session '{}' from {}",
            selected_session.session.name,
            self.options.config_path.display()
        );
        Ok(())
    }

    /// Imports PuTTY sessions from the GUI-supplied source path.
    pub fn import_putty_sessions_from_editor(&mut self, dry_run: bool) -> Result<(), String> {
        let source_path = self.putty_import_path.trim();
        if source_path.is_empty() {
            return Err("Enter a PuTTY registry export, PuTTY session file, or sessions directory path before importing".to_owned());
        }

        let result = import_putty_sessions(source_path, &self.options.config_path, dry_run)
            .map_err(|error| error.to_string())?;
        self.putty_import_report = Some(format_putty_import_report(&result, dry_run));
        if dry_run {
            self.status_message = format!(
                "Dry-run PuTTY import scanned {} session(s): {} new, {} already present, {} skipped",
                result.discovered_sessions,
                result.imported,
                result.already_present,
                result.skipped_total()
            );
        } else {
            self.reload();
            self.status_message = format!(
                "Imported {} PuTTY session(s) into {}",
                result.imported,
                self.options.config_path.display()
            );
        }
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
        self.sync_session_editor_from_selection();
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

    /// Opens or focuses the dedicated terminal window for the selected session.
    pub fn open_selected_session_terminal_window(&mut self) -> Result<(), String> {
        let Some(selected_session) = self.selected_session() else {
            return Err("Select a saved session before opening the terminal window".to_owned());
        };

        match &mut self.terminal_window {
            Some(terminal_window)
                if terminal_window.session_name == selected_session.session.name =>
            {
                terminal_window.visible = true;
                self.status_message = format!(
                    "Showing terminal window for '{}'",
                    selected_session.session.name
                );
                Ok(())
            }
            Some(terminal_window) if terminal_window.has_active_task() => Err(format!(
                "Terminal window '{}' is still busy; reopen that session first or wait for the background task to finish",
                terminal_window.session_name
            )),
            Some(_) | None => {
                let session_name = selected_session.session.name.clone();
                self.terminal_window = Some(TerminalWindowState::new(&selected_session));
                self.status_message = format!("Opened terminal window for '{session_name}'");
                Ok(())
            }
        }
    }

    /// Makes a hidden terminal window visible again.
    pub fn show_terminal_window(&mut self) -> bool {
        let Some(terminal_window) = &mut self.terminal_window else {
            return false;
        };

        if terminal_window.visible {
            return false;
        }

        terminal_window.visible = true;
        self.status_message = format!(
            "Showing terminal window for '{}'",
            terminal_window.session_name
        );
        true
    }

    /// Returns whether a terminal window exists but is currently hidden.
    #[must_use]
    pub fn has_hidden_terminal_window(&self) -> bool {
        self.terminal_window
            .as_ref()
            .is_some_and(|terminal_window| !terminal_window.visible)
    }

    /// Closes or hides the current terminal window.
    pub fn close_terminal_window(&mut self) {
        let Some(terminal_window) = &mut self.terminal_window else {
            return;
        };

        if terminal_window.has_active_task()
            || matches!(
                terminal_window.command_runner_state,
                CommandRunnerState::AwaitingHostKeyConfirmation(_)
            )
            || matches!(
                terminal_window.shell_state,
                InteractiveShellState::AwaitingHostKeyConfirmation(_)
            )
        {
            terminal_window.visible = false;
            self.status_message = format!(
                "Hid terminal window for '{}' while background work continues",
                terminal_window.session_name
            );
            return;
        }

        let session_name = terminal_window.session_name.clone();
        self.terminal_window = None;
        self.status_message = format!("Closed terminal window for '{session_name}'");
    }

    /// Returns a snapshot of the terminal window for rendering.
    #[must_use]
    pub fn terminal_window_snapshot(&self) -> Option<TerminalWindowSnapshot> {
        let terminal_window = self.terminal_window.as_ref()?;
        let stored_session = self.terminal_window_session();
        let launch_preview = stored_session
            .as_ref()
            .map(session_launch_preview)
            .unwrap_or_else(|| {
                format!(
                    "Saved session '{}' is no longer present in the current RusTTY config.",
                    terminal_window.session_name
                )
            });
        let command_preview = stored_session
            .as_ref()
            .map(|stored_session| {
                session_command_preview(stored_session, terminal_window.command_input.as_str())
            })
            .unwrap_or_else(|| {
                format!(
                    "Saved session '{}' is no longer present in the current RusTTY config.",
                    terminal_window.session_name
                )
            });

        Some(terminal_window.snapshot(launch_preview, command_preview))
    }

    /// Returns mutable access to the current terminal-window command input.
    pub fn terminal_window_command_mut(&mut self) -> Option<&mut String> {
        self.terminal_window
            .as_mut()
            .map(|terminal_window| &mut terminal_window.command_input)
    }

    /// Starts a live interactive SSH shell for the current terminal window.
    pub fn start_terminal_window_interactive_shell(
        &mut self,
        terminal_size: TerminalSize,
    ) -> Result<(), String> {
        let session_name = {
            let terminal_window = self.terminal_window.as_ref().ok_or_else(|| {
                "Open a terminal window for a saved session before starting the shell".to_owned()
            })?;
            if terminal_window.has_active_task() {
                return Err("The terminal window is already busy with another SSH task".to_owned());
            }

            terminal_window.session_name.clone()
        };

        let selected_session = self
            .config()
            .and_then(|config| config.find_session(&session_name).cloned())
            .ok_or_else(|| {
                format!(
                    "Saved session '{}' is no longer present in the current RusTTY config",
                    session_name
                )
            })?;

        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.visible = true;
            terminal_window.shell_screen.clear();
            terminal_window.push_transcript(
                TerminalTranscriptTone::Info,
                "Interactive shell requested",
                format!(
                    "Opening a live SSH shell for '{}' in the RusTTY terminal window.",
                    selected_session.session.name
                ),
            );
        }

        match prepare_shell_execution(
            &selected_session,
            &self.options.known_hosts_path,
            terminal_size,
        )? {
            ShellPreparation::Ready(prepared_execution) => {
                if let Some(terminal_window) = &mut self.terminal_window {
                    terminal_window.shell_state =
                        InteractiveShellState::Connecting(prepared_execution.spec.progress.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Info,
                        "Connecting interactive shell",
                        format!(
                            "Starting a PTY-backed SSH shell on {}:{} for '{}'.",
                            prepared_execution.spec.host,
                            prepared_execution.spec.port,
                            prepared_execution.spec.progress.session_name
                        ),
                    );
                }
                self.status_message = format!(
                    "Starting interactive shell for '{}'",
                    prepared_execution.spec.progress.session_name
                );
                self.start_shell_execution(prepared_execution);
            }
            ShellPreparation::RequiresHostKeyProbe(shell_execution_spec) => {
                let progress = shell_execution_spec.progress.clone();
                if let Some(terminal_window) = &mut self.terminal_window {
                    terminal_window.shell_state =
                        InteractiveShellState::ProbingHostKey(progress.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Info,
                        "Probing host key",
                        format!(
                            "Checking the SSH host key for {}:{} before the interactive shell starts.",
                            progress.host, progress.port
                        ),
                    );
                }
                self.status_message =
                    format!("Probing server host key for '{}'", progress.session_name);
                self.start_shell_host_key_probe(shell_execution_spec);
            }
        }

        Ok(())
    }

    /// Sends raw terminal input to the active interactive shell session.
    pub fn send_terminal_window_shell_input(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }

        let terminal_window = self
            .terminal_window
            .as_ref()
            .ok_or_else(|| "No terminal window is currently open".to_owned())?;
        let shell_session = terminal_window
            .shell_session
            .as_ref()
            .ok_or_else(|| "No interactive shell is currently active".to_owned())?;
        shell_session
            .send_input(bytes)
            .map_err(|error| error.to_string())
    }

    /// Resizes the active interactive shell PTY if the terminal surface changed.
    pub fn resize_terminal_window_shell(
        &mut self,
        terminal_size: TerminalSize,
    ) -> Result<(), String> {
        let terminal_window = self
            .terminal_window
            .as_mut()
            .ok_or_else(|| "No terminal window is currently open".to_owned())?;

        let Some(shell_session) = terminal_window.shell_session.as_ref() else {
            return Ok(());
        };

        let current_size = match &terminal_window.shell_state {
            InteractiveShellState::Connecting(progress)
            | InteractiveShellState::Running(progress)
            | InteractiveShellState::ProbingHostKey(progress) => progress.terminal_size,
            InteractiveShellState::Idle
            | InteractiveShellState::AwaitingHostKeyConfirmation(_)
            | InteractiveShellState::Finished(_)
            | InteractiveShellState::Failed(_) => terminal_size,
        };
        if current_size == terminal_size {
            return Ok(());
        }

        match &mut terminal_window.shell_state {
            InteractiveShellState::Connecting(progress)
            | InteractiveShellState::Running(progress)
            | InteractiveShellState::ProbingHostKey(progress) => {
                progress.terminal_size = terminal_size;
            }
            InteractiveShellState::Idle
            | InteractiveShellState::AwaitingHostKeyConfirmation(_)
            | InteractiveShellState::Finished(_)
            | InteractiveShellState::Failed(_) => {}
        }

        shell_session
            .resize(terminal_size)
            .map_err(|error| error.to_string())
    }

    /// Requests a clean shutdown of the active interactive shell session.
    pub fn shutdown_terminal_window_shell(&mut self) -> Result<(), String> {
        let terminal_window = self
            .terminal_window
            .as_ref()
            .ok_or_else(|| "No terminal window is currently open".to_owned())?;
        let shell_session = terminal_window
            .shell_session
            .as_ref()
            .ok_or_else(|| "No interactive shell is currently active".to_owned())?;
        shell_session
            .request_shutdown()
            .map_err(|error| error.to_string())
    }

    /// Starts a background SSH command run for the current terminal window.
    pub fn start_terminal_window_command_run(&mut self) -> Result<(), String> {
        let (session_name, command) = {
            let terminal_window = self.terminal_window.as_ref().ok_or_else(|| {
                "Open a terminal window for a saved session before starting a command".to_owned()
            })?;
            if terminal_window.has_active_task() {
                return Err("The terminal window is already busy with another SSH task".to_owned());
            }

            let command = terminal_window.command_input.trim();
            if command.is_empty() {
                return Err("Enter a remote command before starting the terminal runner".to_owned());
            }

            (terminal_window.session_name.clone(), command.to_owned())
        };

        let selected_session = self
            .config()
            .and_then(|config| config.find_session(&session_name).cloned())
            .ok_or_else(|| {
                format!(
                    "Saved session '{}' is no longer present in the current RusTTY config",
                    session_name
                )
            })?;

        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.visible = true;
            terminal_window.push_transcript(
                TerminalTranscriptTone::Prompt,
                format!("$ {command}"),
                format!(
                    "Queued a saved-session {} command for '{}' through the RusTTY terminal window.",
                    selected_session.session.protocol.label(),
                    selected_session.session.name
                ),
            );
        }

        match prepare_command_execution(
            &selected_session,
            &command,
            &self.options.known_hosts_path,
        )? {
            CommandPreparation::Ready(prepared_execution) => {
                if let Some(terminal_window) = &mut self.terminal_window {
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Info,
                        "Connecting",
                        format!(
                            "Starting SSH command on {}:{} for '{}'.",
                            prepared_execution.spec.host,
                            prepared_execution.spec.port,
                            prepared_execution.spec.progress.session_name
                        ),
                    );
                }
                self.status_message = format!(
                    "Starting terminal-window SSH command for '{}'",
                    prepared_execution.spec.progress.session_name
                );
                self.start_command_execution(prepared_execution);
            }
            CommandPreparation::RequiresHostKeyProbe(command_execution_spec) => {
                let progress = command_execution_spec.progress.clone();
                if let Some(terminal_window) = &mut self.terminal_window {
                    terminal_window.command_runner_state =
                        CommandRunnerState::ProbingHostKey(progress.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Info,
                        "Probing host key",
                        format!(
                            "Checking the SSH host key for {}:{} before credentials are sent.",
                            progress.host, progress.port
                        ),
                    );
                }
                self.status_message =
                    format!("Probing server host key for '{}'", progress.session_name);
                self.start_host_key_probe(command_execution_spec);
            }
        }

        Ok(())
    }

    /// Polls background SSH command activity and updates the launcher state.
    pub fn poll_command_runner(&mut self) {
        self.poll_command_runner_events();
        self.poll_interactive_shell_events();
    }

    fn poll_command_runner_events(&mut self) {
        let Some(terminal_window) = &self.terminal_window else {
            return;
        };
        let Some(receiver) = &terminal_window.command_runner_receiver else {
            return;
        };

        match receiver.try_recv() {
            Ok(CommandRunnerEvent::AwaitingHostKeyConfirmation {
                pending_execution,
                prompt,
            }) => {
                let Some(terminal_window) = &mut self.terminal_window else {
                    return;
                };
                terminal_window.command_runner_receiver = None;
                terminal_window.pending_host_key_execution = Some(*pending_execution);
                terminal_window.command_runner_state =
                    CommandRunnerState::AwaitingHostKeyConfirmation(prompt.clone());
                terminal_window.push_transcript(
                    TerminalTranscriptTone::Warning,
                    "Host-key confirmation required",
                    format!(
                        "RusTTY reached {}:{} for '{}' and needs trust confirmation before credentials are sent. Fingerprint: {}.",
                        prompt.host, prompt.port, prompt.session_name, prompt.fingerprint
                    ),
                );
                self.status_message = format!("Confirm the host key for '{}'", prompt.session_name);
            }
            Ok(CommandRunnerEvent::Finished(report)) => {
                let Some(terminal_window) = &mut self.terminal_window else {
                    return;
                };
                terminal_window.command_runner_receiver = None;
                terminal_window.pending_host_key_execution = None;
                terminal_window.command_runner_state = CommandRunnerState::Finished(report.clone());
                terminal_window.push_transcript(
                    TerminalTranscriptTone::Success,
                    format!("Exit status {}", report.exit_status),
                    format!(
                        "Command finished for '{}' on {}:{}.\nHost key: {} ({})",
                        report.session_name,
                        report.host,
                        report.port,
                        report.host_key_fingerprint,
                        report.host_key_source
                    ),
                );
                if !report.stdout.is_empty() {
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Stdout,
                        "stdout",
                        report.stdout.clone(),
                    );
                }
                if !report.stderr.is_empty() {
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Stderr,
                        "stderr",
                        report.stderr.clone(),
                    );
                }
                if let Some(warning) = &report.warning {
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Warning,
                        "Post-run warning",
                        warning.clone(),
                    );
                }
                self.status_message = format!(
                    "Terminal command for '{}' finished with exit status {}",
                    report.session_name, report.exit_status
                );
            }
            Ok(CommandRunnerEvent::Failed(error)) => {
                let Some(terminal_window) = &mut self.terminal_window else {
                    return;
                };
                terminal_window.command_runner_receiver = None;
                terminal_window.pending_host_key_execution = None;
                terminal_window.command_runner_state = CommandRunnerState::Failed(error.clone());
                terminal_window.push_transcript(
                    TerminalTranscriptTone::Error,
                    "Command failed",
                    error.clone(),
                );
                self.status_message = error;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                let Some(terminal_window) = &mut self.terminal_window else {
                    return;
                };
                terminal_window.command_runner_receiver = None;
                terminal_window.pending_host_key_execution = None;
                let error = "Terminal background task ended unexpectedly".to_owned();
                terminal_window.command_runner_state = CommandRunnerState::Failed(error.clone());
                terminal_window.push_transcript(
                    TerminalTranscriptTone::Error,
                    "Background task ended unexpectedly",
                    error.clone(),
                );
                self.status_message = error;
            }
        }
    }

    fn poll_interactive_shell_events(&mut self) {
        let pending_probe_event = match &self.terminal_window {
            Some(terminal_window) => terminal_window
                .shell_probe_receiver
                .as_ref()
                .map(|receiver| receiver.try_recv()),
            None => return,
        };

        if let Some(probe_result) = pending_probe_event {
            match probe_result {
                Ok(ShellHostKeyProbeEvent::AwaitingHostKeyConfirmation {
                    pending_execution,
                    prompt,
                }) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    terminal_window.shell_probe_receiver = None;
                    terminal_window.pending_shell_execution = Some(*pending_execution);
                    terminal_window.shell_state =
                        InteractiveShellState::AwaitingHostKeyConfirmation(prompt.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Warning,
                        "Host-key confirmation required",
                        format!(
                            "RusTTY reached {}:{} for '{}' and needs trust confirmation before the interactive shell starts. Fingerprint: {}.",
                            prompt.host, prompt.port, prompt.session_name, prompt.fingerprint
                        ),
                    );
                    self.status_message =
                        format!("Confirm the host key for '{}'", prompt.session_name);
                }
                Ok(ShellHostKeyProbeEvent::Failed(error)) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    terminal_window.shell_probe_receiver = None;
                    terminal_window.pending_shell_execution = None;
                    terminal_window.shell_state = InteractiveShellState::Failed(error.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Error,
                        "Interactive shell failed",
                        error.clone(),
                    );
                    self.status_message = error;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    terminal_window.shell_probe_receiver = None;
                    let error = "Interactive shell host-key probe ended unexpectedly".to_owned();
                    terminal_window.shell_state = InteractiveShellState::Failed(error.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Error,
                        "Interactive shell host-key probe ended unexpectedly",
                        error.clone(),
                    );
                    self.status_message = error;
                }
            }
        }

        loop {
            let next_event = {
                let Some(terminal_window) = &self.terminal_window else {
                    return;
                };
                let Some(shell_session) = &terminal_window.shell_session else {
                    return;
                };
                shell_session.try_recv_event()
            };

            match next_event {
                Ok(Some(InteractiveShellEvent::Connected { verified_host_key })) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    let progress = match &terminal_window.shell_state {
                        InteractiveShellState::Connecting(progress)
                        | InteractiveShellState::Running(progress) => progress.clone(),
                        _ => continue,
                    };
                    let fingerprint = host_key_fingerprint(&verified_host_key.public_key);
                    let mut persisted_host_key = false;
                    if terminal_window.persist_shell_host_key_on_connect {
                        match persist_known_host_key(
                            &self.options.known_hosts_path,
                            progress.host.as_str(),
                            progress.port,
                            &verified_host_key.public_key,
                        ) {
                            Ok(result) => persisted_host_key = result.changed,
                            Err(error) => {
                                terminal_window.push_transcript(
                                    TerminalTranscriptTone::Warning,
                                    "Host key could not be saved",
                                    format!(
                                        "Interactive shell connected, but saving the trusted host key failed: {error}"
                                    ),
                                );
                            }
                        }
                    }

                    terminal_window.shell_verified_host_key = Some(verified_host_key.clone());
                    terminal_window.persist_shell_host_key_on_connect = false;
                    terminal_window.shell_persisted_host_key = persisted_host_key;
                    terminal_window.shell_state = InteractiveShellState::Running(progress.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Success,
                        "Interactive shell connected",
                        format!(
                            "Live shell started for '{}' on {}:{}.\nHost key: {} ({})",
                            progress.session_name,
                            progress.host,
                            progress.port,
                            fingerprint,
                            verified_host_key_source_label(verified_host_key.source)
                        ),
                    );
                    self.status_message =
                        format!("Interactive shell for '{}' is live", progress.session_name);
                }
                Ok(Some(InteractiveShellEvent::Stdout(bytes))) => {
                    if let Some(terminal_window) = &mut self.terminal_window {
                        append_shell_output(&mut terminal_window.shell_screen, &bytes);
                    }
                }
                Ok(Some(InteractiveShellEvent::Stderr(bytes))) => {
                    if let Some(terminal_window) = &mut self.terminal_window {
                        append_shell_output(&mut terminal_window.shell_screen, &bytes);
                    }
                }
                Ok(Some(InteractiveShellEvent::Exited { exit_status })) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    let progress = match &terminal_window.shell_state {
                        InteractiveShellState::Running(progress)
                        | InteractiveShellState::Connecting(progress) => progress.clone(),
                        _ => continue,
                    };
                    let Some(verified_host_key) = terminal_window.shell_verified_host_key.clone()
                    else {
                        let error =
                            "Interactive shell completed without a verified host key".to_owned();
                        terminal_window.shell_session = None;
                        terminal_window.shell_state = InteractiveShellState::Failed(error.clone());
                        terminal_window.push_transcript(
                            TerminalTranscriptTone::Error,
                            "Interactive shell metadata missing",
                            error.clone(),
                        );
                        self.status_message = error;
                        continue;
                    };
                    let report = ShellRunReport {
                        session_name: progress.session_name.clone(),
                        host: progress.host.clone(),
                        port: progress.port,
                        exit_status,
                        host_key_fingerprint: host_key_fingerprint(&verified_host_key.public_key),
                        host_key_source: verified_host_key_source_label(verified_host_key.source)
                            .to_owned(),
                        persisted_host_key: terminal_window.shell_persisted_host_key,
                    };
                    terminal_window.shell_session = None;
                    terminal_window.shell_verified_host_key = Some(verified_host_key);
                    terminal_window.shell_state = InteractiveShellState::Finished(report.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Success,
                        format!("Shell exit status {}", report.exit_status),
                        format!(
                            "Interactive shell for '{}' closed on {}:{}.",
                            report.session_name, report.host, report.port
                        ),
                    );
                    self.status_message = format!(
                        "Interactive shell for '{}' exited with status {}",
                        report.session_name, report.exit_status
                    );
                }
                Ok(Some(InteractiveShellEvent::Failed(error))) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    terminal_window.shell_session = None;
                    terminal_window.shell_state = InteractiveShellState::Failed(error.clone());
                    terminal_window.push_transcript(
                        TerminalTranscriptTone::Error,
                        "Interactive shell failed",
                        error.clone(),
                    );
                    self.status_message = error;
                }
                Ok(None) => break,
                Err(_) => {
                    let Some(terminal_window) = &mut self.terminal_window else {
                        return;
                    };
                    if matches!(
                        terminal_window.shell_state,
                        InteractiveShellState::Running(_) | InteractiveShellState::Connecting(_)
                    ) {
                        let error = "Interactive shell session ended unexpectedly".to_owned();
                        terminal_window.shell_state = InteractiveShellState::Failed(error.clone());
                        terminal_window.push_transcript(
                            TerminalTranscriptTone::Error,
                            "Interactive shell ended unexpectedly",
                            error.clone(),
                        );
                        self.status_message = error;
                    }
                    terminal_window.shell_session = None;
                    break;
                }
            }
        }
    }

    /// Returns whether the launcher currently has an active background task.
    #[must_use]
    pub fn has_active_command_task(&self) -> bool {
        self.terminal_window
            .as_ref()
            .is_some_and(TerminalWindowState::has_active_task)
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
        let Some(terminal_window) = &mut self.terminal_window else {
            return;
        };
        if let CommandRunnerState::AwaitingHostKeyConfirmation(prompt) =
            &terminal_window.command_runner_state
        {
            self.status_message = format!(
                "Cancelled host-key confirmation for '{}'",
                prompt.session_name
            );
            terminal_window.push_transcript(
                TerminalTranscriptTone::Warning,
                "Host key rejected",
                format!(
                    "Cancelled the host-key prompt for '{}' at {}:{}.",
                    prompt.session_name, prompt.host, prompt.port
                ),
            );
        }
        terminal_window.pending_host_key_execution = None;
        terminal_window.command_runner_state = CommandRunnerState::Idle;
        if let InteractiveShellState::AwaitingHostKeyConfirmation(prompt) =
            &terminal_window.shell_state
        {
            self.status_message = format!(
                "Cancelled host-key confirmation for '{}'",
                prompt.session_name
            );
            terminal_window.push_transcript(
                TerminalTranscriptTone::Warning,
                "Host key rejected",
                format!(
                    "Cancelled the host-key prompt for '{}' at {}:{}.",
                    prompt.session_name, prompt.host, prompt.port
                ),
            );
            terminal_window.pending_shell_execution = None;
            terminal_window.shell_state = InteractiveShellState::Idle;
        }
    }

    /// Clears the current command-runner result or error.
    pub fn clear_command_runner_state(&mut self) {
        let Some(terminal_window) = &mut self.terminal_window else {
            return;
        };
        terminal_window.pending_host_key_execution = None;
        if !terminal_window.has_active_command_task() {
            terminal_window.command_runner_state = CommandRunnerState::Idle;
        }
        terminal_window.pending_shell_execution = None;
        if !terminal_window.has_active_shell_task() {
            terminal_window.shell_state = InteractiveShellState::Idle;
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
            format!(
                "session_editor_source={}",
                self.session_editor
                    .source_session_name
                    .clone()
                    .unwrap_or_else(|| "new".to_owned())
            ),
            format!(
                "putty_import_path={}",
                if self.putty_import_path.is_empty() {
                    "empty"
                } else {
                    self.putty_import_path.as_str()
                }
            ),
            format!(
                "terminal_window_session={}",
                self.terminal_window
                    .as_ref()
                    .map(|terminal_window| terminal_window.session_name.clone())
                    .unwrap_or_else(|| "none".to_owned())
            ),
            format!(
                "terminal_window_visible={}",
                self.terminal_window
                    .as_ref()
                    .is_some_and(|terminal_window| terminal_window.visible)
            ),
            format!("command_runner_state={}", self.command_runner_state_code()),
            format!(
                "interactive_shell_state={}",
                self.terminal_window
                    .as_ref()
                    .map_or("none", TerminalWindowState::shell_state_code)
            ),
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

    fn editable_config(&self) -> Result<AppConfig, String> {
        match &self.config_state {
            ConfigLoadState::Loaded(config) => Ok(config.clone()),
            ConfigLoadState::Missing => Ok(AppConfig::empty()),
            ConfigLoadState::Error(message) => Err(format!(
                "Fix the config load error before editing sessions: {message}"
            )),
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

    fn sync_session_editor_from_selection(&mut self) {
        self.session_editor = self
            .selected_session()
            .as_ref()
            .map(SessionEditorDraft::from_stored_session)
            .unwrap_or_default();
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
        self.terminal_window
            .as_ref()
            .map_or("none", TerminalWindowState::command_runner_state_code)
    }

    fn resume_pending_host_key_execution(&mut self, persist_host_key: bool) -> Result<(), String> {
        let terminal_window = self
            .terminal_window
            .as_mut()
            .ok_or_else(|| "No terminal window is currently open".to_owned())?;
        if let Some(pending_execution) = terminal_window.pending_host_key_execution.take() {
            let session_name = pending_execution.spec.progress.session_name.clone();
            let host = pending_execution.spec.host.clone();
            let port = pending_execution.spec.port;
            let fingerprint = host_key_fingerprint(&pending_execution.verified_host_key.public_key);

            let prepared_execution = PreparedCommandExecution {
                spec: pending_execution.spec,
                host_key_check: HostKeyCheck::RequireMatch(vec![
                    pending_execution.verified_host_key.public_key.clone(),
                ]),
                persist_host_key_on_success: persist_host_key,
            };

            terminal_window.push_transcript(
                TerminalTranscriptTone::Info,
                if persist_host_key {
                    "Host key trusted and queued for save"
                } else {
                    "Host key trusted for this run"
                },
                format!(
                    "Accepted host key {fingerprint} for '{}' at {}:{}.",
                    session_name, host, port
                ),
            );
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
            return Ok(());
        }

        let Some(pending_execution) = terminal_window.pending_shell_execution.take() else {
            return Err("No host-key confirmation is currently pending".to_owned());
        };
        let session_name = pending_execution.spec.progress.session_name.clone();
        let host = pending_execution.spec.host.clone();
        let port = pending_execution.spec.port;
        let fingerprint = host_key_fingerprint(&pending_execution.verified_host_key.public_key);

        let prepared_execution = PreparedShellExecution {
            spec: pending_execution.spec,
            host_key_check: HostKeyCheck::RequireMatch(vec![
                pending_execution.verified_host_key.public_key.clone(),
            ]),
            persist_host_key_on_connect: persist_host_key,
        };

        terminal_window.push_transcript(
            TerminalTranscriptTone::Info,
            if persist_host_key {
                "Host key trusted and queued for save"
            } else {
                "Host key trusted for this shell"
            },
            format!(
                "Accepted host key {fingerprint} for '{}' at {}:{}.",
                session_name, host, port
            ),
        );
        self.status_message = if persist_host_key {
            format!(
                "Trusted host key for '{}' and queued persistence after connect",
                prepared_execution.spec.progress.session_name
            )
        } else {
            format!(
                "Trusted host key once for '{}'",
                prepared_execution.spec.progress.session_name
            )
        };
        self.start_shell_execution(prepared_execution);
        Ok(())
    }

    fn start_host_key_probe(&mut self, command_execution_spec: CommandExecutionSpec) {
        let (sender, receiver) = mpsc::channel();
        let progress = command_execution_spec.progress.clone();
        let known_hosts_path = command_execution_spec.known_hosts_path.clone();
        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.command_runner_receiver = Some(receiver);
        }

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

    fn start_shell_host_key_probe(&mut self, shell_execution_spec: ShellExecutionSpec) {
        let (sender, receiver) = mpsc::channel();
        let progress = shell_execution_spec.progress.clone();
        let known_hosts_path = shell_execution_spec.known_hosts_path.clone();
        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.shell_probe_receiver = Some(receiver);
        }

        thread::spawn(move || {
            let event = match probe_ssh_host_key(
                shell_execution_spec.host.as_str(),
                shell_execution_spec.port,
            ) {
                Ok(verified_host_key) => {
                    let fingerprint = host_key_fingerprint(&verified_host_key.public_key);
                    ShellHostKeyProbeEvent::AwaitingHostKeyConfirmation {
                        pending_execution: Box::new(PendingShellExecution {
                            spec: shell_execution_spec,
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
                Err(error) => ShellHostKeyProbeEvent::Failed(format!(
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
        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.command_runner_state = CommandRunnerState::Running(progress.clone());
            terminal_window.command_runner_receiver = Some(receiver);
            terminal_window.pending_host_key_execution = None;
        }

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

    fn start_shell_execution(&mut self, prepared_execution: PreparedShellExecution) {
        let progress = prepared_execution.spec.progress.clone();
        let request = prepared_execution.build_request();
        if let Some(terminal_window) = &mut self.terminal_window {
            terminal_window.shell_state = InteractiveShellState::Connecting(progress);
            terminal_window.shell_session = Some(start_interactive_shell_session(&request));
            terminal_window.shell_probe_receiver = None;
            terminal_window.pending_shell_execution = None;
            terminal_window.shell_verified_host_key = None;
            terminal_window.persist_shell_host_key_on_connect =
                prepared_execution.persist_host_key_on_connect;
            terminal_window.shell_persisted_host_key = false;
        }
    }

    fn terminal_window_session(&self) -> Option<StoredSession> {
        let terminal_window = self.terminal_window.as_ref()?;
        self.config()?
            .find_session(&terminal_window.session_name)
            .cloned()
    }

    fn refresh_terminal_window_binding(
        &mut self,
        original_name: Option<&str>,
        stored_session: &StoredSession,
    ) {
        let Some(terminal_window) = &mut self.terminal_window else {
            return;
        };

        if original_name.is_none_or(|name| name != terminal_window.session_name) {
            return;
        }

        terminal_window.session_name = stored_session.session.name.clone();
        terminal_window.protocol = stored_session.session.protocol;
        terminal_window.endpoint = session_endpoint_summary(stored_session);
    }
}

enum CommandPreparation {
    Ready(PreparedCommandExecution),
    RequiresHostKeyProbe(CommandExecutionSpec),
}

enum ShellPreparation {
    Ready(PreparedShellExecution),
    RequiresHostKeyProbe(ShellExecutionSpec),
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

impl PreparedShellExecution {
    fn build_request(&self) -> SshShellRequest {
        SshShellRequest {
            host: self.spec.host.clone(),
            port: self.spec.port,
            username: self.spec.username.clone(),
            authentication_methods: self.spec.authentication_methods.clone(),
            term_type: self.spec.progress.term_type.clone(),
            terminal_size: self.spec.progress.terminal_size,
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

fn prepare_shell_execution(
    stored_session: &StoredSession,
    known_hosts_path: &PathBuf,
    terminal_size: TerminalSize,
) -> Result<ShellPreparation, String> {
    let session = &stored_session.session;
    if session.protocol != Protocol::Ssh {
        return Err(format!(
            "The interactive terminal window currently supports SSH sessions only; '{}' uses {}",
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
    let spec = ShellExecutionSpec {
        progress: ShellRunProgress {
            session_name: session.name.clone(),
            host: host.clone(),
            port,
            term_type: resolve_term_type(),
            terminal_size,
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
        return Ok(ShellPreparation::Ready(PreparedShellExecution {
            spec,
            host_key_check: HostKeyCheck::RequireMatch(trusted_keys),
            persist_host_key_on_connect: false,
        }));
    }

    match session.host_key_policy {
        HostKeyPolicy::Strict => Err(format!(
            "Session '{}' requires a trusted host key in {} before the interactive shell can connect",
            session.name,
            known_hosts_path.display()
        )),
        HostKeyPolicy::AcceptNew => Ok(ShellPreparation::Ready(PreparedShellExecution {
            spec,
            host_key_check: HostKeyCheck::TrustOnFirstUse,
            persist_host_key_on_connect: true,
        })),
        HostKeyPolicy::Ask => Ok(ShellPreparation::RequiresHostKeyProbe(spec)),
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

fn resolve_term_type() -> String {
    env::var("TERM")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "xterm-256color".to_owned())
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

fn normalized_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn parse_optional_port(raw_port: &str) -> Result<Option<u16>, String> {
    let trimmed = raw_port.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    trimmed
        .parse::<u16>()
        .map(Some)
        .map_err(|_| format!("Invalid port value: {trimmed}"))
}

fn parse_forward_lines<T>(
    session_name: &str,
    raw_value: &str,
    build_spec: impl Fn(String, String) -> T,
) -> Result<Vec<T>, String> {
    let mut rules = Vec::new();
    for (index, line) in raw_value.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some((source, target)) = trimmed.split_once("->") else {
            return Err(format!(
                "Session '{session_name}' forwarding line {} must use 'source -> target'",
                index + 1
            ));
        };
        let source = source.trim();
        let target = target.trim();
        if source.is_empty() || target.is_empty() {
            return Err(format!(
                "Session '{session_name}' forwarding line {} must define both source and target",
                index + 1
            ));
        }

        rules.push(build_spec(source.to_owned(), target.to_owned()));
    }

    Ok(rules)
}

fn parse_dynamic_forward_lines(raw_value: &str) -> Vec<DynamicForwardSpec> {
    raw_value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| DynamicForwardSpec::new(line.to_owned()))
        .collect()
}

fn render_forward_lines(forwards: &[PortForwardSpec]) -> String {
    forwards
        .iter()
        .map(|forward| format!("{} -> {}", forward.source, forward.target))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_remote_forward_lines(forwards: &[RemoteForwardSpec]) -> String {
    forwards
        .iter()
        .map(|forward| format!("{} -> {}", forward.source, forward.target))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_dynamic_forward_lines(forwards: &[DynamicForwardSpec]) -> String {
    forwards
        .iter()
        .map(|forward| forward.listen.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_putty_import_report(result: &ImportPuttySessionsResult, dry_run: bool) -> String {
    format!(
        "Mode: {}\nSource: {}\nDestination: {}\nDiscovered sessions: {}\nImported: {}\nAlready present: {}\nSkipped unsupported protocol: {}\nSkipped unlaunchable: {}\nSkipped conflicting: {}\nSkipped malformed: {}\nSkipped outside target: {}\nSkipped blank/comment: {}\nSkipped total: {}",
        if dry_run { "Dry run" } else { "Imported" },
        result.source_path.display(),
        result.destination_path.display(),
        result.discovered_sessions,
        result.imported,
        result.already_present,
        result.skipped_unsupported_protocol,
        result.skipped_unlaunchable,
        result.skipped_conflicting,
        result.skipped_malformed,
        result.skipped_outside_target,
        result.skipped_blank_or_comment,
        result.skipped_total(),
    )
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

fn session_endpoint_summary(stored_session: &StoredSession) -> String {
    let session = &stored_session.session;
    match (session.host.as_deref(), session.effective_port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => "No host configured".to_owned(),
    }
}

fn append_shell_output(buffer: &mut String, bytes: &[u8]) {
    let chunk = String::from_utf8_lossy(bytes);
    let mut chars = chunk.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\u{1b}' => consume_ansi_escape(&mut chars),
            '\r' => {}
            '\u{8}' => {
                let _ = buffer.pop();
            }
            '\n' | '\t' => buffer.push(character),
            control if control.is_control() => {}
            other => buffer.push(other),
        }
    }

    trim_shell_screen(buffer);
}

fn consume_ansi_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(next) = chars.next() else {
        return;
    };

    match next {
        '[' => {
            for character in chars.by_ref() {
                if ('@'..='~').contains(&character) {
                    break;
                }
            }
        }
        ']' => {
            for character in chars.by_ref() {
                if character == '\u{7}' {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn trim_shell_screen(buffer: &mut String) {
    const MAX_SHELL_SCREEN_CHARS: usize = 120_000;
    if buffer.chars().count() <= MAX_SHELL_SCREEN_CHARS {
        return;
    }

    let trimmed = buffer
        .chars()
        .rev()
        .take(MAX_SHELL_SCREEN_CHARS)
        .collect::<Vec<_>>();
    *buffer = trimmed.into_iter().rev().collect();
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

    use rustty_config::{AppConfig, StoredSession, load_config, save_config};
    use rustty_core::{Protocol, SessionConfig};

    use super::{
        CommandRunnerState, LauncherModel, LauncherOptions, QuickConnectDraft, append_shell_output,
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
    fn terminal_window_stays_bound_to_the_opened_session() {
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
            SessionConfig::new("lab-ssh", Protocol::Ssh)
                .with_host("lab.example")
                .with_username("ops"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let mut model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        model
            .open_selected_session_terminal_window()
            .expect("selected session should open a terminal window");
        model.select_session("lab-ssh");

        let snapshot = model
            .terminal_window_snapshot()
            .expect("terminal window snapshot should be present");
        assert_eq!(snapshot.session_name, "prod-ssh");
    }

    #[test]
    fn terminal_window_command_runner_requires_non_empty_remote_command() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        save_config(&config_path, &AppConfig::sample()).expect("config should save");

        let mut model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        model
            .open_selected_session_terminal_window()
            .expect("sample SSH session should open a terminal window");
        let error = model
            .start_terminal_window_command_run()
            .expect_err("empty command should be rejected");

        assert!(error.contains("Enter a remote command"));
        let snapshot = model
            .terminal_window_snapshot()
            .expect("terminal window snapshot should be present");
        assert_eq!(snapshot.command_runner_state, CommandRunnerState::Idle);
    }

    #[test]
    fn terminal_window_command_runner_rejects_non_ssh_saved_sessions_before_runtime_work() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let mut config = AppConfig::empty();
        config.add_session(StoredSession::new(
            SessionConfig::new("legacy", Protocol::Telnet).with_host("bbs.example"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let mut model = LauncherModel::load(LauncherOptions::new(config_path, known_hosts_path));
        model
            .open_selected_session_terminal_window()
            .expect("selected session should open a terminal window");
        model
            .terminal_window_command_mut()
            .expect("terminal window should expose its command input")
            .push_str("help");
        let error = model
            .start_terminal_window_command_run()
            .expect_err("non-SSH sessions should be rejected");

        assert!(error.contains("supports SSH sessions only"));
        let snapshot = model
            .terminal_window_snapshot()
            .expect("terminal window snapshot should be present");
        assert_eq!(snapshot.command_runner_state, CommandRunnerState::Idle);
    }

    #[test]
    fn append_shell_output_strips_basic_ansi_sequences() {
        let mut buffer = String::new();
        append_shell_output(&mut buffer, b"\x1b[32mhello\x1b[0m\r\nworld");

        assert_eq!(buffer, "hello\nworld");
    }

    #[test]
    fn append_shell_output_applies_backspace() {
        let mut buffer = String::new();
        append_shell_output(&mut buffer, b"helo\x08lo");

        assert_eq!(buffer, "hello");
    }

    #[test]
    fn saving_new_session_from_missing_config_creates_real_config() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let mut model =
            LauncherModel::load(LauncherOptions::new(config_path.clone(), known_hosts_path));

        let draft = model.session_editor_mut();
        draft.name = "prod-ssh".to_owned();
        draft.host = "prod.example".to_owned();
        draft.username = "ops".to_owned();
        draft.password_env = "RUSTTY_PROD_PASSWORD".to_owned();

        model
            .save_session_editor()
            .expect("new session should save into a fresh config");

        let loaded = load_config(&config_path).expect("config should load after save");
        let saved_session = loaded
            .find_session("prod-ssh")
            .expect("saved session should be present");
        assert_eq!(saved_session.session.host.as_deref(), Some("prod.example"));
        assert_eq!(
            saved_session.session.password_env.as_deref(),
            Some("RUSTTY_PROD_PASSWORD")
        );
    }

    #[test]
    fn saving_selected_session_can_rename_it() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let mut config = AppConfig::empty();
        config.add_session(StoredSession::new(
            SessionConfig::new("prod-ssh", Protocol::Ssh)
                .with_host("prod.example")
                .with_username("ops"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let mut model =
            LauncherModel::load(LauncherOptions::new(config_path.clone(), known_hosts_path));
        let draft = model.session_editor_mut();
        draft.name = "prod-renamed".to_owned();
        draft.host = "renamed.example".to_owned();

        model
            .save_session_editor()
            .expect("selected session should be renamed");

        let loaded = load_config(&config_path).expect("config should load");
        assert!(loaded.find_session("prod-ssh").is_none());
        let renamed = loaded
            .find_session("prod-renamed")
            .expect("renamed session should be present");
        assert_eq!(renamed.session.host.as_deref(), Some("renamed.example"));
    }

    #[test]
    fn deleting_selected_session_removes_it_from_config() {
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
            SessionConfig::new("lab-serial", Protocol::Serial).with_host("/dev/ttyUSB0"),
        ));
        save_config(&config_path, &config).expect("config should save");

        let mut model =
            LauncherModel::load(LauncherOptions::new(config_path.clone(), known_hosts_path));
        model
            .delete_selected_session()
            .expect("selected session should delete");

        let loaded = load_config(&config_path).expect("config should load");
        assert!(loaded.find_session("prod-ssh").is_none());
        assert!(loaded.find_session("lab-serial").is_some());
    }

    #[test]
    fn putty_import_dry_run_reports_without_writing_config() {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        let known_hosts_path = workspace.join("known_hosts");
        let source_path = workspace.join("putty-session.txt");
        std::fs::write(
            &source_path,
            "HostName=prod.example.com\nProtocol=ssh\nUserName=ops\n",
        )
        .expect("source file should be written");

        let mut model =
            LauncherModel::load(LauncherOptions::new(config_path.clone(), known_hosts_path));
        *model.putty_import_path_mut() = source_path.display().to_string();
        model
            .import_putty_sessions_from_editor(true)
            .expect("dry-run import should succeed");

        assert!(!config_path.exists());
        let report = model
            .putty_import_report()
            .expect("dry-run import should produce a report");
        assert!(report.contains("Dry run"));
        assert!(report.contains("Discovered sessions: 1"));
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
