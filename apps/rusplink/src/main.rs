use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use rustty_config::{AppConfig, ImportSource, StoredSession, default_config_path, load_config};
use rustty_core::{HostKeyPolicy, PortForwardSpec, Protocol, StorageFormat};

const USAGE: &str = "\
rusplink bootstrap CLI

Usage:
  rusplink --help
  rusplink --show-default-config-path
  rusplink --list-sessions [--config PATH]
  rusplink --list-sessions --config=PATH
  rusplink --session NAME [--config PATH] [--port PORT] --dry-run [-- COMMAND...]
  rusplink --session=NAME [--config PATH] [--port PORT] --dry-run [-- COMMAND...]
  rusplink TARGET [--port PORT] --dry-run [-- COMMAND...]

Notes:
  TARGET supports host, user@host, host:port, and [ipv6-host]:port forms.
  Transport execution is not implemented yet; use --dry-run to inspect the
  resolved SSH plan.
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    ShowDefaultConfigPath,
    ListSessions { config_path: Option<PathBuf> },
    Plan(PlanRequest),
}

#[derive(Debug, Eq, PartialEq)]
struct PlanRequest {
    config_path: Option<PathBuf>,
    target: InvocationTarget,
    port_override: Option<u16>,
    dry_run: bool,
    remote_command: Vec<String>,
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
}

#[derive(Debug, Eq, PartialEq)]
enum PlanOrigin {
    Session,
    Direct,
}

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    match run(std::env::args().skip(1), &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run<I, W>(arguments: I, writer: &mut W) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
    W: Write,
{
    match parse_command(arguments)? {
        Command::Help => {
            write!(writer, "{USAGE}").map_err(|error| error.to_string())?;
            Ok(())
        }
        Command::ShowDefaultConfigPath => show_default_config_path(writer),
        Command::ListSessions { config_path } => list_sessions(config_path, writer),
        Command::Plan(request) => {
            let plan = build_connection_plan(&request)?;
            if !request.dry_run {
                return Err(
                    "rusplink transport execution is not implemented yet; rerun with --dry-run \
                     to inspect the resolved SSH plan"
                        .to_owned(),
                );
            }

            print_connection_plan(writer, &plan)
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
    let mut remote_command = Vec::new();

    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--show-default-config-path" => {
                show_default_config_path = true;
            }
            "--list-sessions" => {
                list_sessions = true;
            }
            "--dry-run" => {
                dry_run = true;
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
                } else if let Some(raw_port) = argument.strip_prefix("--port=") {
                    let port = parse_port(raw_port)?;
                    set_option_once(&mut port_override, port, "duplicate --port flag")?;
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
        if list_sessions
            || config_path.is_some()
            || session_name.is_some()
            || direct_target.is_some()
            || port_override.is_some()
            || dry_run
            || !remote_command.is_empty()
        {
            return Err(usage_error(
                "--show-default-config-path does not accept additional arguments",
            ));
        }

        return Ok(Command::ShowDefaultConfigPath);
    }

    if list_sessions {
        if session_name.is_some()
            || direct_target.is_some()
            || port_override.is_some()
            || dry_run
            || !remote_command.is_empty()
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
            target: InvocationTarget::Session(session_name),
            port_override,
            dry_run,
            remote_command,
        })),
        (None, Some(target)) => {
            if config_path.is_some() {
                return Err(usage_error(
                    "--config requires --session or --list-sessions in the current bootstrap CLI",
                ));
            }

            Ok(Command::Plan(PlanRequest {
                config_path: None,
                target: InvocationTarget::Direct(target),
                port_override,
                dry_run,
                remote_command,
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

fn list_sessions<W>(config_path: Option<PathBuf>, writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    let (config_path, config) = load_resolved_config(config_path)?;

    writeln!(writer, "config_path={}", config_path.display()).map_err(|error| error.to_string())?;
    writeln!(writer, "name\tprotocol\thost\tport\timported_from")
        .map_err(|error| error.to_string())?;

    for stored_session in config.sessions() {
        let session = &stored_session.session;
        let host = session.host.as_deref().unwrap_or("-");
        let port = render_port(session.effective_port());
        let imported_from = render_import_source(stored_session.imported_from);
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}",
            session.name,
            session.protocol.label(),
            host,
            port,
            imported_from
        )
        .map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn build_connection_plan(request: &PlanRequest) -> Result<ConnectionPlan, String> {
    match &request.target {
        InvocationTarget::Session(session_name) => {
            let (config_path, config) = load_resolved_config(request.config_path.clone())?;
            let stored_session = config.find_session(session_name).ok_or_else(|| {
                format!(
                    "RusTTY session not found: {session_name} (config: {})",
                    config_path.display()
                )
            })?;
            build_session_plan(stored_session, config_path, request)
        }
        InvocationTarget::Direct(target) => build_direct_plan(target, request),
    }
}

fn build_session_plan(
    stored_session: &StoredSession,
    config_path: PathBuf,
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

    Ok(ConnectionPlan {
        origin: PlanOrigin::Session,
        config_path: Some(config_path),
        session_name: Some(session.name.clone()),
        protocol: session.protocol,
        username: None,
        host,
        port,
        remote_command: request.remote_command.clone(),
        host_key_policy: session.host_key_policy,
        port_forwards: session.port_forwards.clone(),
        saved_in: Some(session.saved_in),
        imported_from: stored_session.imported_from,
    })
}

fn build_direct_plan(
    target: &DirectTarget,
    request: &PlanRequest,
) -> Result<ConnectionPlan, String> {
    let port = request.port_override.or(target.port).unwrap_or(22);
    if target.host.is_empty() {
        return Err("direct target host must not be empty".to_owned());
    }

    Ok(ConnectionPlan {
        origin: PlanOrigin::Direct,
        config_path: None,
        session_name: None,
        protocol: Protocol::Ssh,
        username: target.username.clone(),
        host: target.host.clone(),
        port,
        remote_command: request.remote_command.clone(),
        host_key_policy: HostKeyPolicy::Ask,
        port_forwards: Vec::new(),
        saved_in: None,
        imported_from: None,
    })
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
    writeln!(
        writer,
        "host_key_policy={}",
        render_host_key_policy(plan.host_key_policy)
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
        remote_command.join(" ")
    }
}

fn render_host_key_policy(policy: HostKeyPolicy) -> &'static str {
    match policy {
        HostKeyPolicy::Ask => "ask",
        HostKeyPolicy::Strict => "strict",
        HostKeyPolicy::AcceptNew => "accept_new",
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

    use super::{Command, DirectTarget, PlanRequest, run};
    use crate::{InvocationTarget, parse_command};

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
    fn parses_session_dry_run_with_remote_command() {
        assert_eq!(
            parse_command([
                "--session".to_owned(),
                "production".to_owned(),
                "--config".to_owned(),
                "/tmp/rustty.toml".to_owned(),
                "--port".to_owned(),
                "2222".to_owned(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "uname".to_owned(),
                "-a".to_owned(),
            ]),
            Ok(Command::Plan(PlanRequest {
                config_path: Some(PathBuf::from("/tmp/rustty.toml")),
                target: InvocationTarget::Session("production".to_owned()),
                port_override: Some(2222),
                dry_run: true,
                remote_command: vec!["uname".to_owned(), "-a".to_owned()],
            }))
        );
    }

    #[test]
    fn parses_direct_target_with_bracketed_ipv6_host() {
        assert_eq!(
            parse_command(["ops@[2001:db8::1]:2200".to_owned(), "--dry-run".to_owned(),]),
            Ok(Command::Plan(PlanRequest {
                config_path: None,
                target: InvocationTarget::Direct(DirectTarget {
                    username: Some("ops".to_owned()),
                    host: "2001:db8::1".to_owned(),
                    port: Some(2200),
                }),
                port_override: None,
                dry_run: true,
                remote_command: Vec::new(),
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
    fn list_sessions_prints_tabular_output() {
        let config_path = write_config(AppConfig::sample());
        let mut output = Vec::new();

        run(
            [
                "--list-sessions".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
            ],
            &mut output,
        )
        .expect("listing sessions should succeed");

        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("config_path="));
        assert!(output.contains("name\tprotocol\thost\tport\timported_from"));
        assert!(output.contains("example-ssh\tSSH\texample.com\t22\t-"));
    }

    #[test]
    fn dry_run_session_prints_resolved_plan() {
        let config_path = write_config(AppConfig::sample());
        let mut output = Vec::new();

        run(
            [
                "--session".to_owned(),
                "example-ssh".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "hostname".to_owned(),
            ],
            &mut output,
        )
        .expect("session dry-run should succeed");

        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("origin=session"));
        assert!(output.contains("session_name=example-ssh"));
        assert!(output.contains("host=example.com"));
        assert!(output.contains("port=22"));
        assert!(output.contains("command=hostname"));
        assert!(output.contains(&format!("config_path={}", config_path.display())));
    }

    #[test]
    fn direct_target_dry_run_prints_username_and_port() {
        let mut output = Vec::new();

        run(
            [
                "ops@[2001:db8::10]:2222".to_owned(),
                "--dry-run".to_owned(),
                "--".to_owned(),
                "uptime".to_owned(),
            ],
            &mut output,
        )
        .expect("direct target dry-run should succeed");

        let output = String::from_utf8(output).expect("output should be valid UTF-8");
        assert!(output.contains("origin=direct"));
        assert!(output.contains("username=ops"));
        assert!(output.contains("host=2001:db8::10"));
        assert!(output.contains("port=2222"));
        assert!(output.contains("command=uptime"));
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
        )
        .expect_err("non-SSH sessions should be rejected");

        assert!(error.contains("only supports SSH sessions"));
        assert!(error.contains("Telnet"));
    }

    #[test]
    fn connection_requests_require_dry_run_until_transport_exists() {
        let error = run(["example.com".to_owned()], &mut Vec::new())
            .expect_err("transport execution should stay disabled");
        assert!(error.contains("rerun with --dry-run"));
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
