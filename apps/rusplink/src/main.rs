use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process,
};

use rustty_config::{
    AppConfig, ImportSource, StoredSession, default_config_path, default_known_hosts_path,
    load_config, load_known_host_keys, persist_known_host_key,
};
use rustty_core::{HostKeyPolicy, PortForwardSpec, Protocol, StorageFormat};
use rustty_transport::{
    HostKeyCheck, SshExecRequest, SshShellRequest, TerminalSize, VerifiedHostKey,
    VerifiedHostKeySource, execute_ssh_command, run_interactive_shell,
};

const DEFAULT_PASSWORD_ENV: &str = "RUSTTY_SSH_PASSWORD";
const USAGE: &str = "\
rusplink bootstrap CLI

Usage:
  rusplink --help
  rusplink --show-default-config-path
  rusplink --show-default-known-hosts-path
  rusplink --list-sessions [--config PATH]
  rusplink --list-sessions --config=PATH
  rusplink --session NAME [--config PATH] [--known-hosts PATH] [--username USER] [--password-env ENV] [--unsafe-accept-host-key] [--port PORT] --dry-run [-- COMMAND...]
  rusplink --session=NAME [--config PATH] [--known-hosts PATH] [--username USER] [--password-env ENV] [--unsafe-accept-host-key] [--port PORT] --dry-run [-- COMMAND...]
  rusplink --session NAME [--config PATH] [--known-hosts PATH] [--username USER] [--password-env ENV] [--unsafe-accept-host-key] [--port PORT] [-- COMMAND...]
  rusplink TARGET [--known-hosts PATH] [--username USER] [--password-env ENV] [--unsafe-accept-host-key] [--port PORT] --dry-run [-- COMMAND...]
  rusplink TARGET [--known-hosts PATH] [--username USER] [--password-env ENV] [--unsafe-accept-host-key] [--port PORT] [-- COMMAND...]

Notes:
  TARGET supports host, user@host, host:port, and [ipv6-host]:port forms.
  Live SSH execution currently supports password authentication for remote
  exec requests and interactive shell sessions.
  Host keys are verified against the RusTTY known-hosts file. `accept_new`
  sessions persist the first trusted server key automatically; `ask` still
  needs a pre-trusted key because interactive confirmation is not implemented.
  Use --unsafe-accept-host-key only for disposable/bootstrap testing.
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    ShowDefaultConfigPath,
    ShowDefaultKnownHostsPath,
    ListSessions { config_path: Option<PathBuf> },
    Plan(PlanRequest),
}

#[derive(Debug, Eq, PartialEq)]
struct PlanRequest {
    config_path: Option<PathBuf>,
    known_hosts_path: Option<PathBuf>,
    target: InvocationTarget,
    port_override: Option<u16>,
    dry_run: bool,
    remote_command: Vec<String>,
    username_override: Option<String>,
    password_env_override: Option<String>,
    unsafe_accept_host_key: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum InvocationTarget {
    Session(String),
    Direct(DirectTarget),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectTarget {
    username: Option<String>,
    host: String,
    port: Option<u16>,
}

#[derive(Debug, Eq, PartialEq)]
struct ConnectionPlan {
    origin: PlanOrigin,
    config_path: Option<PathBuf>,
    known_hosts_path: PathBuf,
    session_name: Option<String>,
    protocol: Protocol,
    username: Option<String>,
    host: String,
    port: u16,
    remote_command: Vec<String>,
    host_key_policy: HostKeyPolicy,
    port_forwards: Vec<PortForwardSpec>,
    saved_in: Option<StorageFormat>,
    imported_from: Option<ImportSource>,
    password_env_var: String,
    unsafe_accept_host_key: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum PlanOrigin {
    Session,
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunOutcome {
    Success,
    RemoteExit(u32),
}

fn main() {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    match run(std::env::args().skip(1), &mut stdout, &mut stderr) {
        Ok(RunOutcome::Success) => process::exit(0),
        Ok(RunOutcome::RemoteExit(status)) => {
            let code = u8::try_from(status).unwrap_or(1);
            process::exit(i32::from(code));
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn run<I, W, E>(arguments: I, writer: &mut W, error_writer: &mut E) -> Result<RunOutcome, String>
where
    I: IntoIterator<Item = String>,
    W: Write,
    E: Write,
{
    match parse_command(arguments)? {
        Command::Help => {
            write!(writer, "{USAGE}").map_err(|error| error.to_string())?;
            Ok(RunOutcome::Success)
        }
        Command::ShowDefaultConfigPath => {
            show_default_config_path(writer)?;
            Ok(RunOutcome::Success)
        }
        Command::ShowDefaultKnownHostsPath => {
            show_default_known_hosts_path(writer)?;
            Ok(RunOutcome::Success)
        }
        Command::ListSessions { config_path } => {
            list_sessions(config_path, writer)?;
            Ok(RunOutcome::Success)
        }
        Command::Plan(request) => {
            let plan = build_connection_plan(&request)?;
            if request.dry_run {
                print_connection_plan(writer, &plan)?;
                return Ok(RunOutcome::Success);
            }

            execute_connection_plan(&plan, writer, error_writer)
        }
    }
}

fn parse_command<I>(arguments: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.is_empty() {
        return Ok(Command::Help);
    }

    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--help" | "-h") {
        return Ok(Command::Help);
    }

    let mut config_path = None;
    let mut list_sessions = false;
    let mut session_name = None;
    let mut direct_target = None;
    let mut port_override = None;
    let mut dry_run = false;
    let mut show_default_config_path = false;
    let mut show_default_known_hosts_path = false;
    let mut remote_command = Vec::new();
    let mut username_override = None;
    let mut password_env_override = None;
    let mut unsafe_accept_host_key = false;
    let mut known_hosts_path = None;

    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--show-default-config-path" => {
                show_default_config_path = true;
            }
            "--show-default-known-hosts-path" => {
                show_default_known_hosts_path = true;
            }
            "--list-sessions" => {
                list_sessions = true;
            }
            "--dry-run" => {
                dry_run = true;
            }
            "--unsafe-accept-host-key" => {
                unsafe_accept_host_key = true;
            }
            "--config" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --config"))?;
                set_option_once(
                    &mut config_path,
                    PathBuf::from(raw_path),
                    "duplicate --config flag",
                )?;
                index += 1;
            }
            "--known-hosts" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --known-hosts"))?;
                set_option_once(
                    &mut known_hosts_path,
                    PathBuf::from(raw_path),
                    "duplicate --known-hosts flag",
                )?;
                index += 1;
            }
            "--session" => {
                let raw_name = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --session"))?;
                set_option_once(
                    &mut session_name,
                    raw_name.clone(),
                    "duplicate --session flag",
                )?;
                index += 1;
            }
            "--port" => {
                let raw_port = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --port"))?;
                let port = parse_port(raw_port)?;
                set_option_once(&mut port_override, port, "duplicate --port flag")?;
                index += 1;
            }
            "--username" => {
                let raw_username = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --username"))?;
                set_option_once(
                    &mut username_override,
                    raw_username.clone(),
                    "duplicate --username flag",
                )?;
                index += 1;
            }
            "--password-env" => {
                let raw_env = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --password-env"))?;
                set_option_once(
                    &mut password_env_override,
                    raw_env.clone(),
                    "duplicate --password-env flag",
                )?;
                index += 1;
            }
            "--" => {
                remote_command.extend(arguments[(index + 1)..].iter().cloned());
                break;
            }
            _ => {
                if let Some(raw_path) = argument.strip_prefix("--config=") {
                    set_option_once(
                        &mut config_path,
                        PathBuf::from(raw_path),
                        "duplicate --config flag",
                    )?;
                } else if let Some(raw_name) = argument.strip_prefix("--session=") {
                    set_option_once(
                        &mut session_name,
                        raw_name.to_owned(),
                        "duplicate --session flag",
                    )?;
                } else if let Some(raw_path) = argument.strip_prefix("--known-hosts=") {
                    set_option_once(
                        &mut known_hosts_path,
                        PathBuf::from(raw_path),
                        "duplicate --known-hosts flag",
                    )?;
                } else if let Some(raw_port) = argument.strip_prefix("--port=") {
                    let port = parse_port(raw_port)?;
                    set_option_once(&mut port_override, port, "duplicate --port flag")?;
                } else if let Some(raw_username) = argument.strip_prefix("--username=") {
                    set_option_once(
                        &mut username_override,
                        raw_username.to_owned(),
                        "duplicate --username flag",
                    )?;
                } else if let Some(raw_env) = argument.strip_prefix("--password-env=") {
                    set_option_once(
                        &mut password_env_override,
                        raw_env.to_owned(),
                        "duplicate --password-env flag",
                    )?;
                } else if matches!(argument.as_str(), "--help" | "-h") {
                    return Err(usage_error(
                        "help must be requested without other arguments",
                    ));
                } else if argument.starts_with('-') {
                    return Err(usage_error(format!("unsupported argument: {argument}")));
                } else {
                    let target = parse_direct_target(argument)?;
                    set_option_once(
                        &mut direct_target,
                        target,
                        format!("unexpected positional argument: {argument}"),
                    )?;
                }
            }
        }
        index += 1;
    }

    if show_default_config_path {
        if show_default_known_hosts_path
            || list_sessions
            || config_path.is_some()
            || known_hosts_path.is_some()
            || session_name.is_some()
            || direct_target.is_some()
            || port_override.is_some()
            || dry_run
            || !remote_command.is_empty()
            || username_override.is_some()
            || password_env_override.is_some()
            || unsafe_accept_host_key
        {
            return Err(usage_error(
                "--show-default-config-path does not accept additional arguments",
            ));
        }

        return Ok(Command::ShowDefaultConfigPath);
    }

    if show_default_known_hosts_path {
        if show_default_config_path
            || list_sessions
            || config_path.is_some()
            || known_hosts_path.is_some()
            || session_name.is_some()
            || direct_target.is_some()
            || port_override.is_some()
            || dry_run
            || !remote_command.is_empty()
            || username_override.is_some()
            || password_env_override.is_some()
            || unsafe_accept_host_key
        {
            return Err(usage_error(
                "--show-default-known-hosts-path does not accept additional arguments",
            ));
        }

        return Ok(Command::ShowDefaultKnownHostsPath);
    }

    if list_sessions {
        if session_name.is_some()
            || direct_target.is_some()
            || port_override.is_some()
            || dry_run
            || !remote_command.is_empty()
            || username_override.is_some()
            || password_env_override.is_some()
            || unsafe_accept_host_key
            || known_hosts_path.is_some()
        {
            return Err(usage_error(
                "--list-sessions cannot be combined with connection arguments",
            ));
        }

        return Ok(Command::ListSessions { config_path });
    }

    match (session_name, direct_target) {
        (Some(_), Some(_)) => Err(usage_error(
            "cannot combine --session with a direct target argument",
        )),
        (Some(session_name), None) => Ok(Command::Plan(PlanRequest {
            config_path,
            known_hosts_path,
            target: InvocationTarget::Session(session_name),
            port_override,
            dry_run,
            remote_command,
            username_override,
            password_env_override,
            unsafe_accept_host_key,
        })),
        (None, Some(target)) => {
            if config_path.is_some() {
                return Err(usage_error(
                    "--config requires --session or --list-sessions in the current bootstrap CLI",
                ));
            }

            Ok(Command::Plan(PlanRequest {
                config_path: None,
                known_hosts_path,
                target: InvocationTarget::Direct(target),
                port_override,
                dry_run,
                remote_command,
                username_override,
                password_env_override,
                unsafe_accept_host_key,
            }))
        }
        (None, None) => Err(usage_error("missing session name or target host")),
    }
}

fn show_default_config_path<W>(writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    let path = default_config_path().map_err(|error| error.to_string())?;
    writeln!(writer, "{}", path.display()).map_err(|error| error.to_string())
}

fn show_default_known_hosts_path<W>(writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    let path = default_known_hosts_path().map_err(|error| error.to_string())?;
    writeln!(writer, "{}", path.display()).map_err(|error| error.to_string())
}

fn list_sessions<W>(config_path: Option<PathBuf>, writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    let (config_path, config) = load_resolved_config(config_path)?;

    writeln!(writer, "config_path={}", config_path.display()).map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "name\tprotocol\thost\tport\tusername\tpassword_env\timported_from"
    )
    .map_err(|error| error.to_string())?;

    for stored_session in config.sessions() {
        let session = &stored_session.session;
        let host = session.host.as_deref().unwrap_or("-");
        let port = render_port(session.effective_port());
        let username = session.username.as_deref().unwrap_or("-");
        let password_env = session.password_env.as_deref().unwrap_or("-");
        let imported_from = render_import_source(stored_session.imported_from);
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            session.name,
            session.protocol.label(),
            host,
            port,
            username,
            password_env,
            imported_from
        )
        .map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn build_connection_plan(request: &PlanRequest) -> Result<ConnectionPlan, String> {
    let known_hosts_path = resolve_known_hosts_path(request.known_hosts_path.clone())?;

    match &request.target {
        InvocationTarget::Session(session_name) => {
            let (config_path, config) = load_resolved_config(request.config_path.clone())?;
            let stored_session = config.find_session(session_name).ok_or_else(|| {
                format!(
                    "RusTTY session not found: {session_name} (config: {})",
                    config_path.display()
                )
            })?;
            build_session_plan(stored_session, config_path, known_hosts_path, request)
        }
        InvocationTarget::Direct(target) => build_direct_plan(target, known_hosts_path, request),
    }
}

fn build_session_plan(
    stored_session: &StoredSession,
    config_path: PathBuf,
    known_hosts_path: PathBuf,
    request: &PlanRequest,
) -> Result<ConnectionPlan, String> {
    let session = &stored_session.session;
    if session.protocol != Protocol::Ssh {
        return Err(format!(
            "rusplink only supports SSH sessions right now; '{}' uses {}",
            session.name,
            session.protocol.label()
        ));
    }

    let host = session
        .host
        .clone()
        .ok_or_else(|| format!("RusTTY session '{}' is missing a host", session.name))?;
    let port = request
        .port_override
        .or_else(|| session.effective_port())
        .unwrap_or(22);
    let password_env_var = request
        .password_env_override
        .clone()
        .or_else(|| session.password_env.clone())
        .unwrap_or_else(|| DEFAULT_PASSWORD_ENV.to_owned());

    Ok(ConnectionPlan {
        origin: PlanOrigin::Session,
        config_path: Some(config_path),
        known_hosts_path,
        session_name: Some(session.name.clone()),
        protocol: session.protocol,
        username: request
            .username_override
            .clone()
            .or_else(|| session.username.clone()),
        host,
        port,
        remote_command: request.remote_command.clone(),
        host_key_policy: session.host_key_policy,
        port_forwards: session.port_forwards.clone(),
        saved_in: Some(session.saved_in),
        imported_from: stored_session.imported_from,
        password_env_var,
        unsafe_accept_host_key: request.unsafe_accept_host_key,
    })
}

fn build_direct_plan(
    target: &DirectTarget,
    known_hosts_path: PathBuf,
    request: &PlanRequest,
) -> Result<ConnectionPlan, String> {
    let port = request.port_override.or(target.port).unwrap_or(22);
    if target.host.is_empty() {
        return Err("direct target host must not be empty".to_owned());
    }

    let password_env_var = request
        .password_env_override
        .clone()
        .unwrap_or_else(|| DEFAULT_PASSWORD_ENV.to_owned());

    Ok(ConnectionPlan {
        origin: PlanOrigin::Direct,
        config_path: None,
        known_hosts_path,
        session_name: None,
        protocol: Protocol::Ssh,
        username: request
            .username_override
            .clone()
            .or_else(|| target.username.clone()),
        host: target.host.clone(),
        port,
        remote_command: request.remote_command.clone(),
        host_key_policy: HostKeyPolicy::Ask,
        port_forwards: Vec::new(),
        saved_in: None,
        imported_from: None,
        password_env_var,
        unsafe_accept_host_key: request.unsafe_accept_host_key,
    })
}

fn execute_connection_plan<W, E>(
    plan: &ConnectionPlan,
    writer: &mut W,
    error_writer: &mut E,
) -> Result<RunOutcome, String>
where
    W: Write,
    E: Write,
{
    let host_key_check = resolve_host_key_check(plan)?;
    let username = resolve_execution_username(plan.username.as_deref())?;
    let password = resolve_password(&plan.password_env_var)?;

    if plan.remote_command.is_empty() {
        let request = SshShellRequest {
            host: plan.host.clone(),
            port: plan.port,
            username,
            password,
            term_type: resolve_term_type(),
            terminal_size: resolve_terminal_size()?,
            host_key_check,
        };
        let result = run_interactive_shell(&request)
            .map_err(|error| format!("rusplink SSH transport failed: {error}"))?;
        persist_accepted_host_key(plan, &result.verified_host_key, error_writer)?;
        return Ok(RunOutcome::RemoteExit(result.exit_status));
    }

    let request = SshExecRequest {
        host: plan.host.clone(),
        port: plan.port,
        username,
        password,
        command: render_remote_command(&plan.remote_command),
        host_key_check,
    };
    let result = execute_ssh_command(&request)
        .map_err(|error| format!("rusplink SSH transport failed: {error}"))?;
    persist_accepted_host_key(plan, &result.verified_host_key, error_writer)?;

    writer
        .write_all(&result.stdout)
        .map_err(|error| error.to_string())?;
    error_writer
        .write_all(&result.stderr)
        .map_err(|error| error.to_string())?;

    Ok(RunOutcome::RemoteExit(result.exit_status))
}

fn print_connection_plan<W>(writer: &mut W, plan: &ConnectionPlan) -> Result<(), String>
where
    W: Write,
{
    writeln!(writer, "mode=dry-run").map_err(|error| error.to_string())?;
    writeln!(writer, "origin={}", render_origin(&plan.origin))
        .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "config_path={}",
        plan.config_path
            .as_ref()
            .map_or_else(|| "-".to_owned(), |path| path.display().to_string())
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "known_hosts_path={}",
        plan.known_hosts_path.display()
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "session_name={}",
        plan.session_name.as_deref().unwrap_or("-")
    )
    .map_err(|error| error.to_string())?;
    writeln!(writer, "protocol={}", plan.protocol.label()).map_err(|error| error.to_string())?;
    writeln!(writer, "host={}", plan.host).map_err(|error| error.to_string())?;
    writeln!(writer, "port={}", plan.port).map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "username={}",
        plan.username.as_deref().unwrap_or("-")
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "command={}",
        render_remote_command(&plan.remote_command)
    )
    .map_err(|error| error.to_string())?;
    writeln!(writer, "password_env={}", plan.password_env_var)
        .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "host_key_policy={}",
        render_host_key_policy(plan.host_key_policy)
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "transport_host_key_check={}",
        render_transport_host_key_check(plan)
    )
    .map_err(|error| error.to_string())?;
    writeln!(writer, "saved_in={}", render_storage_format(plan.saved_in))
        .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "imported_from={}",
        render_import_source(plan.imported_from)
    )
    .map_err(|error| error.to_string())?;
    writeln!(writer, "port_forwards={}", plan.port_forwards.len())
        .map_err(|error| error.to_string())?;

    for (index, port_forward) in plan.port_forwards.iter().enumerate() {
        writeln!(
            writer,
            "port_forward_{index}={}->{}",
            port_forward.source, port_forward.target
        )
        .map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn load_resolved_config(config_path: Option<PathBuf>) -> Result<(PathBuf, AppConfig), String> {
    let config_path = resolve_config_path(config_path)?;
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    Ok((config_path, config))
}

fn resolve_config_path(config_path: Option<PathBuf>) -> Result<PathBuf, String> {
    config_path.map_or_else(
        || default_config_path().map_err(|error| error.to_string()),
        Ok,
    )
}

fn resolve_known_hosts_path(known_hosts_path: Option<PathBuf>) -> Result<PathBuf, String> {
    known_hosts_path.map_or_else(
        || default_known_hosts_path().map_err(|error| error.to_string()),
        Ok,
    )
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
            "SSH username is required; supply user@host, --username, or a USER/USERNAME \
             environment variable"
                .to_owned()
        })
}

fn resolve_password(password_env_var: &str) -> Result<String, String> {
    let password = env::var(password_env_var)
        .map_err(|_| format!("missing SSH password in environment variable {password_env_var}"))?;
    if password.is_empty() {
        return Err(format!(
            "SSH password environment variable {password_env_var} must not be empty"
        ));
    }

    Ok(password)
}

fn resolve_host_key_check(plan: &ConnectionPlan) -> Result<HostKeyCheck, String> {
    if plan.unsafe_accept_host_key {
        return Ok(HostKeyCheck::AcceptAny);
    }

    let known_host_keys = load_known_host_keys(&plan.known_hosts_path, &plan.host, plan.port)
        .map_err(|error| error.to_string())?;
    let trusted_keys = known_host_keys
        .into_iter()
        .map(|known_host| known_host.public_key)
        .collect::<Vec<_>>();

    if !trusted_keys.is_empty() {
        return Ok(HostKeyCheck::RequireMatch(trusted_keys));
    }

    match plan.host_key_policy {
        HostKeyPolicy::Ask => Err(format!(
            "interactive host-key confirmation is not implemented yet and no trusted key was found in {}; rerun with --dry-run or --unsafe-accept-host-key",
            plan.known_hosts_path.display()
        )),
        HostKeyPolicy::Strict => Err(format!(
            "strict host-key verification requires a trusted key in {}; rerun with --dry-run or --unsafe-accept-host-key",
            plan.known_hosts_path.display()
        )),
        HostKeyPolicy::AcceptNew => Ok(HostKeyCheck::TrustOnFirstUse),
    }
}

fn resolve_term_type() -> String {
    env::var("TERM")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "xterm-256color".to_owned())
}

fn resolve_terminal_size() -> Result<TerminalSize, String> {
    TerminalSize::from_current_terminal().map_err(|error| {
        format!("cannot determine local terminal size for interactive SSH shell: {error}")
    })
}

fn persist_accepted_host_key<E>(
    plan: &ConnectionPlan,
    verified_host_key: &VerifiedHostKey,
    error_writer: &mut E,
) -> Result<(), String>
where
    E: Write,
{
    if plan.unsafe_accept_host_key
        || plan.host_key_policy != HostKeyPolicy::AcceptNew
        || verified_host_key.source != VerifiedHostKeySource::TrustOnFirstUse
    {
        return Ok(());
    }

    let persist_result = persist_known_host_key(
        &plan.known_hosts_path,
        &plan.host,
        plan.port,
        &verified_host_key.public_key,
    )
    .map_err(|error| error.to_string())?;

    if persist_result.changed {
        writeln!(
            error_writer,
            "rusplink: trusted new host key for {}:{} and saved it to {}",
            plan.host,
            plan.port,
            persist_result.path.display()
        )
        .map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn parse_direct_target(input: &str) -> Result<DirectTarget, String> {
    if input.is_empty() {
        return Err(usage_error("target must not be empty"));
    }

    let (username, host_port) = match input.rsplit_once('@') {
        Some((raw_username, raw_host_port))
            if raw_username.is_empty() || raw_host_port.is_empty() =>
        {
            return Err(usage_error(format!("invalid SSH target: {input}")));
        }
        Some((raw_username, raw_host_port)) => (Some(raw_username.to_owned()), raw_host_port),
        None => (None, input),
    };

    let (host, port) = parse_host_and_port(host_port)?;
    Ok(DirectTarget {
        username,
        host,
        port,
    })
}

fn parse_host_and_port(input: &str) -> Result<(String, Option<u16>), String> {
    if let Some(bracketed) = input.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| usage_error(format!("invalid bracketed target: {input}")))?;
        if host.is_empty() {
            return Err(usage_error("target host must not be empty"));
        }

        if suffix.is_empty() {
            return Ok((host.to_owned(), None));
        }

        let raw_port = suffix
            .strip_prefix(':')
            .ok_or_else(|| usage_error(format!("invalid bracketed target: {input}")))?;
        return Ok((host.to_owned(), Some(parse_port(raw_port)?)));
    }

    match input.matches(':').count() {
        0 => Ok((input.to_owned(), None)),
        1 => {
            let (host, raw_port) = input
                .rsplit_once(':')
                .ok_or_else(|| usage_error(format!("invalid SSH target: {input}")))?;
            if host.is_empty() {
                return Err(usage_error("target host must not be empty"));
            }
            Ok((host.to_owned(), Some(parse_port(raw_port)?)))
        }
        _ => Ok((input.to_owned(), None)),
    }
}

fn parse_port(raw_port: &str) -> Result<u16, String> {
    raw_port.parse::<u16>().map_err(|_| {
        usage_error(format!(
            "invalid TCP port: {raw_port}; expected an integer between 0 and 65535"
        ))
    })
}

fn render_origin(origin: &PlanOrigin) -> &'static str {
    match origin {
        PlanOrigin::Session => "session",
        PlanOrigin::Direct => "direct",
    }
}

fn render_remote_command(remote_command: &[String]) -> String {
    if remote_command.is_empty() {
        "-".to_owned()
    } else {
        remote_command
            .iter()
            .map(|argument| shell_escape(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn shell_escape(argument: &str) -> String {
    if argument.is_empty() {
        return "''".to_owned();
    }

    if argument.chars().all(is_shell_safe_character) {
        return argument.to_owned();
    }

    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

fn is_shell_safe_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '_' | '-' | '.' | '/' | ':' | '@' | ',' | '+' | '='
        )
}

fn render_host_key_policy(policy: HostKeyPolicy) -> &'static str {
    match policy {
        HostKeyPolicy::Ask => "ask",
        HostKeyPolicy::Strict => "strict",
        HostKeyPolicy::AcceptNew => "accept_new",
    }
}

fn render_transport_host_key_check(plan: &ConnectionPlan) -> &'static str {
    if plan.unsafe_accept_host_key {
        "unsafe_accept_any"
    } else if plan.host_key_policy == HostKeyPolicy::AcceptNew {
        "known_hosts_or_accept_new"
    } else {
        "known_hosts_required"
    }
}

fn render_storage_format(storage_format: Option<StorageFormat>) -> &'static str {
    match storage_format {
        Some(StorageFormat::Rustty) => "rustty",
        Some(StorageFormat::PuttyImportOnly) => "putty_import_only",
        None => "-",
    }
}

fn render_import_source(import_source: Option<ImportSource>) -> &'static str {
    match import_source {
        Some(ImportSource::PuttyRegistry) => "putty_registry",
        Some(ImportSource::PuttySessionFile) => "putty_session_file",
        Some(ImportSource::OpenSshConfig) => "open_ssh_config",
        None => "-",
    }
}

fn render_port(port: Option<u16>) -> String {
    port.map_or_else(|| "-".to_owned(), |port| port.to_string())
}

fn set_option_once<T>(
    slot: &mut Option<T>,
    value: T,
    duplicate_message: impl AsRef<str>,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(usage_error(duplicate_message));
    }

    *slot = Some(value);
    Ok(())
}

fn usage_error(message: impl AsRef<str>) -> String {
    format!("{}\n\n{USAGE}", message.as_ref())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rustty_config::{AppConfig, StoredSession, save_config};
    use rustty_core::{Protocol, SessionConfig};

    use super::{Command, DEFAULT_PASSWORD_ENV, DirectTarget, PlanRequest, RunOutcome, run};
    use crate::{InvocationTarget, parse_command, render_remote_command, resolve_host_key_check};

    #[test]
    fn defaults_to_help_when_no_arguments_are_supplied() {
        assert_eq!(parse_command(Vec::<String>::new()), Ok(Command::Help));
    }

    #[test]
    fn parses_list_sessions_with_attached_config_path() {
        assert_eq!(
            parse_command([
                "--list-sessions".to_owned(),
                "--config=/tmp/rustty.toml".to_owned()
            ]),
            Ok(Command::ListSessions {
                config_path: Some(PathBuf::from("/tmp/rustty.toml")),
            })
        );
    }

    #[test]
    fn parses_session_dry_run_with_transport_flags() {
        assert_eq!(
            parse_command([
                "--session".to_owned(),
                "production".to_owned(),
                "--config".to_owned(),
                "/tmp/rustty.toml".to_owned(),
                "--known-hosts".to_owned(),
                "/tmp/known_hosts".to_owned(),
                "--username".to_owned(),
                "ops".to_owned(),
                "--password-env".to_owned(),
                "RUSTTY_TEST_PASSWORD".to_owned(),
                "--unsafe-accept-host-key".to_owned(),
                "--port".to_owned(),
                "2222".to_owned(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "uname".to_owned(),
                "-a".to_owned(),
            ]),
            Ok(Command::Plan(PlanRequest {
                config_path: Some(PathBuf::from("/tmp/rustty.toml")),
                known_hosts_path: Some(PathBuf::from("/tmp/known_hosts")),
                target: InvocationTarget::Session("production".to_owned()),
                port_override: Some(2222),
                dry_run: true,
                remote_command: vec!["uname".to_owned(), "-a".to_owned()],
                username_override: Some("ops".to_owned()),
                password_env_override: Some("RUSTTY_TEST_PASSWORD".to_owned()),
                unsafe_accept_host_key: true,
            }))
        );
    }

    #[test]
    fn rejects_combining_default_path_flags() {
        let error = parse_command([
            "--show-default-config-path".to_owned(),
            "--show-default-known-hosts-path".to_owned(),
        ])
        .expect_err("default path flags should stay mutually exclusive");

        assert!(error.contains("--show-default-config-path"));
    }

    #[test]
    fn parses_direct_target_with_bracketed_ipv6_host() {
        assert_eq!(
            parse_command(["ops@[2001:db8::1]:2200".to_owned(), "--dry-run".to_owned(),]),
            Ok(Command::Plan(PlanRequest {
                config_path: None,
                known_hosts_path: None,
                target: InvocationTarget::Direct(DirectTarget {
                    username: Some("ops".to_owned()),
                    host: "2001:db8::1".to_owned(),
                    port: Some(2200),
                }),
                port_override: None,
                dry_run: true,
                remote_command: Vec::new(),
                username_override: None,
                password_env_override: None,
                unsafe_accept_host_key: false,
            }))
        );
    }

    #[test]
    fn rejects_config_for_direct_targets() {
        let error = parse_command([
            "example.com".to_owned(),
            "--config".to_owned(),
            "/tmp/rustty.toml".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect_err("direct targets should reject --config during bootstrap");
        assert!(error.contains("--config requires --session or --list-sessions"));
    }

    #[test]
    fn shell_escapes_remote_command_arguments() {
        assert_eq!(
            render_remote_command(&["echo".to_owned(), "hello world".to_owned()]),
            "echo 'hello world'"
        );
        assert_eq!(
            render_remote_command(&["printf".to_owned(), "it's".to_owned()]),
            "printf 'it'\"'\"'s'"
        );
    }

    #[test]
    fn list_sessions_prints_tabular_output() {
        let config_path = write_config(AppConfig::sample());
        let mut output = Vec::new();
        let mut error_output = Vec::new();

        let outcome = run(
            [
                "--list-sessions".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
            ],
            &mut output,
            &mut error_output,
        )
        .expect("listing sessions should succeed");

        assert_eq!(outcome, RunOutcome::Success);
        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("config_path="));
        assert!(
            output.contains("name\tprotocol\thost\tport\tusername\tpassword_env\timported_from")
        );
        assert!(
            output
                .contains("example-ssh\tSSH\texample.com\t22\tops\tRUSTTY_EXAMPLE_SSH_PASSWORD\t-")
        );
        assert!(error_output.is_empty());
    }

    #[test]
    fn session_dry_run_uses_stored_username_and_password_env_defaults() {
        let config_path = write_config(AppConfig::sample());
        let known_hosts_path = temporary_workspace().join("known_hosts");
        let mut output = Vec::new();
        let mut error_output = Vec::new();

        let outcome = run(
            [
                "--session".to_owned(),
                "example-ssh".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
                "--known-hosts".to_owned(),
                known_hosts_path.display().to_string(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "hostname".to_owned(),
            ],
            &mut output,
            &mut error_output,
        )
        .expect("session dry-run should succeed");

        assert_eq!(outcome, RunOutcome::Success);
        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("username=ops"));
        assert!(output.contains("password_env=RUSTTY_EXAMPLE_SSH_PASSWORD"));
        assert!(error_output.is_empty());
    }

    #[test]
    fn dry_run_session_prints_resolved_plan() {
        let config_path = write_config(AppConfig::sample());
        let known_hosts_path = temporary_workspace().join("known_hosts");
        let mut output = Vec::new();
        let mut error_output = Vec::new();

        let outcome = run(
            [
                "--session".to_owned(),
                "example-ssh".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
                "--known-hosts".to_owned(),
                known_hosts_path.display().to_string(),
                "--username".to_owned(),
                "ops".to_owned(),
                "--password-env".to_owned(),
                "RUSTTY_TEST_PASSWORD".to_owned(),
                "--unsafe-accept-host-key".to_owned(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "hostname".to_owned(),
            ],
            &mut output,
            &mut error_output,
        )
        .expect("session dry-run should succeed");

        assert_eq!(outcome, RunOutcome::Success);
        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("origin=session"));
        assert!(output.contains("session_name=example-ssh"));
        assert!(output.contains("host=example.com"));
        assert!(output.contains("port=22"));
        assert!(output.contains(&format!("known_hosts_path={}", known_hosts_path.display())));
        assert!(output.contains("username=ops"));
        assert!(output.contains("password_env=RUSTTY_TEST_PASSWORD"));
        assert!(output.contains("transport_host_key_check=unsafe_accept_any"));
        assert!(output.contains("command=hostname"));
        assert!(output.contains(&format!("config_path={}", config_path.display())));
        assert!(error_output.is_empty());
    }

    #[test]
    fn direct_target_dry_run_prints_username_and_port() {
        let known_hosts_path = temporary_workspace().join("known_hosts");
        let mut output = Vec::new();
        let mut error_output = Vec::new();

        let outcome = run(
            [
                "ops@[2001:db8::10]:2222".to_owned(),
                "--known-hosts".to_owned(),
                known_hosts_path.display().to_string(),
                "--password-env".to_owned(),
                "RUSTTY_TEST_PASSWORD".to_owned(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "uptime".to_owned(),
            ],
            &mut output,
            &mut error_output,
        )
        .expect("direct target dry-run should succeed");

        assert_eq!(outcome, RunOutcome::Success);
        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("origin=direct"));
        assert!(output.contains("username=ops"));
        assert!(output.contains("host=2001:db8::10"));
        assert!(output.contains("port=2222"));
        assert!(output.contains(&format!("known_hosts_path={}", known_hosts_path.display())));
        assert!(output.contains("password_env=RUSTTY_TEST_PASSWORD"));
        assert!(output.contains("command=uptime"));
        assert!(error_output.is_empty());
    }

    #[test]
    fn session_dry_run_rejects_non_ssh_sessions() {
        let mut config = AppConfig::sample();
        config.add_session(StoredSession::new(
            SessionConfig::new("legacy-telnet", Protocol::Telnet).with_host("legacy.example"),
        ));
        let config_path = write_config(config);

        let error = run(
            [
                "--session".to_owned(),
                "legacy-telnet".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
                "--dry-run".to_owned(),
            ],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("non-SSH sessions should be rejected");

        assert!(error.contains("only supports SSH sessions"));
        assert!(error.contains("Telnet"));
    }

    #[test]
    fn live_execution_requires_explicit_host_key_override_for_bootstrap() {
        let known_hosts_path = temporary_workspace().join("known_hosts");
        let error = run(
            [
                "ops@example.com".to_owned(),
                "--known-hosts".to_owned(),
                known_hosts_path.display().to_string(),
                "--".to_owned(),
                "uptime".to_owned(),
            ],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("host-key confirmation should be required");

        assert!(error.contains("--unsafe-accept-host-key"));
    }

    #[test]
    fn interactive_shell_requires_trusted_host_key_when_policy_is_ask() {
        let known_hosts_path = temporary_workspace().join("known_hosts");
        let error = run(
            [
                "ops@example.com".to_owned(),
                "--known-hosts".to_owned(),
                known_hosts_path.display().to_string(),
            ],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("interactive shells should require host-key trust before connecting");

        assert!(error.contains("interactive host-key confirmation is not implemented yet"));
        assert!(error.contains("known_hosts"));
    }

    #[test]
    fn resolve_host_key_check_uses_known_hosts_matches() {
        let known_hosts_path = temporary_workspace().join("known_hosts");
        std::fs::write(
            &known_hosts_path,
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti\n",
        )
        .expect("known-hosts file should be written");

        let plan = super::ConnectionPlan {
            origin: super::PlanOrigin::Direct,
            config_path: None,
            known_hosts_path,
            session_name: None,
            protocol: Protocol::Ssh,
            username: Some("ops".to_owned()),
            host: "example.com".to_owned(),
            port: 22,
            remote_command: vec!["uptime".to_owned()],
            host_key_policy: rustty_core::HostKeyPolicy::Ask,
            port_forwards: Vec::new(),
            saved_in: None,
            imported_from: None,
            password_env_var: DEFAULT_PASSWORD_ENV.to_owned(),
            unsafe_accept_host_key: false,
        };

        let host_key_check =
            resolve_host_key_check(&plan).expect("stored host key should allow the connection");
        match host_key_check {
            rustty_transport::HostKeyCheck::RequireMatch(keys) => assert_eq!(keys.len(), 1),
            rustty_transport::HostKeyCheck::AcceptAny
            | rustty_transport::HostKeyCheck::TrustOnFirstUse => {
                panic!("expected stored known-host verification")
            }
        }
    }

    fn write_config(config: AppConfig) -> PathBuf {
        let workspace = temporary_workspace();
        let config_path = workspace.join("config.toml");
        save_config(&config_path, &config).expect("config should be written");
        config_path
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rusplink-cli-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
