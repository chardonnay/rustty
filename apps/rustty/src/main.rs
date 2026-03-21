use std::{path::PathBuf, process::ExitCode};

use rustty_config::{
    AppConfig, default_config_path, default_known_hosts_path, import_known_hosts,
    import_putty_host_keys, import_putty_sessions, init_config, load_config,
};

const USAGE: &str = "\
RusTTY bootstrap CLI

Usage:
  rustty
  rustty --help
  rustty --print-sample-config
  rustty --show-default-config-path
  rustty --show-default-known-hosts-path
  rustty --init-config [PATH]
  rustty --init-config=PATH
  rustty --validate-config [PATH]
  rustty --validate-config=PATH
  rustty --import-known-hosts SOURCE [--known-hosts PATH] [--dry-run]
  rustty --import-known-hosts=SOURCE [--known-hosts PATH] [--dry-run]
  rustty --import-putty-host-keys SOURCE [--known-hosts PATH] [--dry-run]
  rustty --import-putty-host-keys=SOURCE [--known-hosts PATH] [--dry-run]
  rustty --import-putty-sessions SOURCE [--config PATH] [--dry-run]
  rustty --import-putty-sessions=SOURCE [--config PATH] [--dry-run]
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Gui,
    Help,
    PrintSampleConfig,
    ShowDefaultConfigPath,
    ShowDefaultKnownHostsPath,
    InitConfig(Option<PathBuf>),
    ValidateConfig(Option<PathBuf>),
    ImportKnownHosts {
        source_path: PathBuf,
        known_hosts_path: Option<PathBuf>,
        dry_run: bool,
    },
    ImportPuttyHostKeys {
        source_path: PathBuf,
        known_hosts_path: Option<PathBuf>,
        dry_run: bool,
    },
    ImportPuttySessions {
        source_path: PathBuf,
        config_path: Option<PathBuf>,
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match parse_command(std::env::args().skip(1))? {
        Command::Gui => open_gui(),
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::PrintSampleConfig => print_sample_config(),
        Command::ShowDefaultConfigPath => show_default_config_path(),
        Command::ShowDefaultKnownHostsPath => show_default_known_hosts_path(),
        Command::InitConfig(path) => initialize_config(path),
        Command::ValidateConfig(path) => validate_config(path),
        Command::ImportKnownHosts {
            source_path,
            known_hosts_path,
            dry_run,
        } => import_known_hosts_file(source_path, known_hosts_path, dry_run),
        Command::ImportPuttyHostKeys {
            source_path,
            known_hosts_path,
            dry_run,
        } => import_putty_host_keys_file(source_path, known_hosts_path, dry_run),
        Command::ImportPuttySessions {
            source_path,
            config_path,
            dry_run,
        } => import_putty_sessions_file(source_path, config_path, dry_run),
    }
}

fn open_gui() -> Result<(), String> {
    let config_path = resolve_config_path(None)?;
    let known_hosts_path = resolve_known_hosts_path(None)?;
    rustty_ui::run_native(rustty_ui::LauncherOptions::new(
        config_path,
        known_hosts_path,
    ))
}

fn parse_command<I>(arguments: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.is_empty() {
        return Ok(Command::Gui);
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum PrimaryCommand {
        Help,
        PrintSampleConfig,
        ShowDefaultConfigPath,
        ShowDefaultKnownHostsPath,
        InitConfig(Option<PathBuf>),
        ValidateConfig(Option<PathBuf>),
        ImportKnownHosts(PathBuf),
        ImportPuttyHostKeys(PathBuf),
        ImportPuttySessions(PathBuf),
    }

    let mut primary_command = None;
    let mut import_known_hosts_destination = None;
    let mut import_config_destination = None;
    let mut dry_run = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--help" | "-h" => {
                set_command_once(&mut primary_command, PrimaryCommand::Help, argument)?;
            }
            "--print-sample-config" => {
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::PrintSampleConfig,
                    argument,
                )?;
            }
            "--show-default-config-path" => {
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ShowDefaultConfigPath,
                    argument,
                )?;
            }
            "--show-default-known-hosts-path" => {
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ShowDefaultKnownHostsPath,
                    argument,
                )?;
            }
            "--init-config" => {
                let path = consume_optional_path(&arguments, &mut index);
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::InitConfig(path.map(PathBuf::from)),
                    argument,
                )?;
            }
            "--validate-config" => {
                let path = consume_optional_path(&arguments, &mut index);
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ValidateConfig(path.map(PathBuf::from)),
                    argument,
                )?;
            }
            "--import-known-hosts" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for --import-known-hosts\n\n{USAGE}"))?;
                if raw_path.starts_with("--") {
                    return Err(format!("missing value for --import-known-hosts\n\n{USAGE}"));
                }
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ImportKnownHosts(PathBuf::from(raw_path)),
                    argument,
                )?;
                index += 1;
            }
            "--import-putty-host-keys" => {
                let raw_path = arguments.get(index + 1).ok_or_else(|| {
                    format!("missing value for --import-putty-host-keys\n\n{USAGE}")
                })?;
                if raw_path.starts_with("--") {
                    return Err(format!(
                        "missing value for --import-putty-host-keys\n\n{USAGE}"
                    ));
                }
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ImportPuttyHostKeys(PathBuf::from(raw_path)),
                    argument,
                )?;
                index += 1;
            }
            "--import-putty-sessions" => {
                let raw_path = arguments.get(index + 1).ok_or_else(|| {
                    format!("missing value for --import-putty-sessions\n\n{USAGE}")
                })?;
                if raw_path.starts_with("--") {
                    return Err(format!(
                        "missing value for --import-putty-sessions\n\n{USAGE}"
                    ));
                }
                set_command_once(
                    &mut primary_command,
                    PrimaryCommand::ImportPuttySessions(PathBuf::from(raw_path)),
                    argument,
                )?;
                index += 1;
            }
            "--known-hosts" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for --known-hosts\n\n{USAGE}"))?;
                if raw_path.starts_with("--") {
                    return Err(format!("missing value for --known-hosts\n\n{USAGE}"));
                }
                set_option_once(
                    &mut import_known_hosts_destination,
                    PathBuf::from(raw_path),
                    "duplicate --known-hosts flag",
                )?;
                index += 1;
            }
            "--config" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for --config\n\n{USAGE}"))?;
                if raw_path.starts_with("--") {
                    return Err(format!("missing value for --config\n\n{USAGE}"));
                }
                set_option_once(
                    &mut import_config_destination,
                    PathBuf::from(raw_path),
                    "duplicate --config flag",
                )?;
                index += 1;
            }
            "--dry-run" => {
                dry_run = true;
            }
            _ => {
                if let Some(path) = argument.strip_prefix("--init-config=") {
                    set_command_once(
                        &mut primary_command,
                        PrimaryCommand::InitConfig(Some(PathBuf::from(path))),
                        "--init-config",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--validate-config=") {
                    set_command_once(
                        &mut primary_command,
                        PrimaryCommand::ValidateConfig(Some(PathBuf::from(path))),
                        "--validate-config",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--import-known-hosts=") {
                    set_command_once(
                        &mut primary_command,
                        PrimaryCommand::ImportKnownHosts(PathBuf::from(path)),
                        "--import-known-hosts",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--import-putty-host-keys=") {
                    set_command_once(
                        &mut primary_command,
                        PrimaryCommand::ImportPuttyHostKeys(PathBuf::from(path)),
                        "--import-putty-host-keys",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--import-putty-sessions=") {
                    set_command_once(
                        &mut primary_command,
                        PrimaryCommand::ImportPuttySessions(PathBuf::from(path)),
                        "--import-putty-sessions",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--known-hosts=") {
                    set_option_once(
                        &mut import_known_hosts_destination,
                        PathBuf::from(path),
                        "duplicate --known-hosts flag",
                    )?;
                } else if let Some(path) = argument.strip_prefix("--config=") {
                    set_option_once(
                        &mut import_config_destination,
                        PathBuf::from(path),
                        "duplicate --config flag",
                    )?;
                } else {
                    return Err(format!("unsupported argument: {argument}\n\n{USAGE}"));
                }
            }
        }

        index += 1;
    }

    match primary_command {
        Some(PrimaryCommand::Help) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::Help)
        }
        Some(PrimaryCommand::PrintSampleConfig) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::PrintSampleConfig)
        }
        Some(PrimaryCommand::ShowDefaultConfigPath) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::ShowDefaultConfigPath)
        }
        Some(PrimaryCommand::ShowDefaultKnownHostsPath) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::ShowDefaultKnownHostsPath)
        }
        Some(PrimaryCommand::InitConfig(path)) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::InitConfig(path))
        }
        Some(PrimaryCommand::ValidateConfig(path)) => {
            reject_import_only_flags(
                import_known_hosts_destination,
                import_config_destination,
                dry_run,
            )?;
            Ok(Command::ValidateConfig(path))
        }
        Some(PrimaryCommand::ImportKnownHosts(source_path)) => {
            if import_config_destination.is_some() {
                return Err(format!(
                    "--config requires --import-putty-sessions\n\n{USAGE}"
                ));
            }
            Ok(Command::ImportKnownHosts {
                source_path,
                known_hosts_path: import_known_hosts_destination,
                dry_run,
            })
        }
        Some(PrimaryCommand::ImportPuttyHostKeys(source_path)) => {
            if import_config_destination.is_some() {
                return Err(format!(
                    "--config requires --import-putty-sessions\n\n{USAGE}"
                ));
            }
            Ok(Command::ImportPuttyHostKeys {
                source_path,
                known_hosts_path: import_known_hosts_destination,
                dry_run,
            })
        }
        Some(PrimaryCommand::ImportPuttySessions(source_path)) => {
            if import_known_hosts_destination.is_some() {
                return Err(format!(
                    "--known-hosts requires a host-key import command\n\n{USAGE}"
                ));
            }
            Ok(Command::ImportPuttySessions {
                source_path,
                config_path: import_config_destination,
                dry_run,
            })
        }
        None => Err(format!("unsupported argument combination\n\n{USAGE}")),
    }
}

fn print_sample_config() -> Result<(), String> {
    let config = AppConfig::sample()
        .to_toml_string()
        .map_err(|error| format!("failed to render sample config: {error}"))?;
    print!("{config}");
    Ok(())
}

fn show_default_config_path() -> Result<(), String> {
    let path = default_config_path().map_err(|error| error.to_string())?;
    println!("{}", path.display());
    Ok(())
}

fn show_default_known_hosts_path() -> Result<(), String> {
    let path = default_known_hosts_path().map_err(|error| error.to_string())?;
    println!("{}", path.display());
    Ok(())
}

fn initialize_config(path: Option<PathBuf>) -> Result<(), String> {
    let path = resolve_config_path(path)?;
    let result = init_config(&path).map_err(|error| error.to_string())?;
    if result.created {
        println!("initialized RusTTY config at {}", result.path.display());
    } else {
        println!(
            "RusTTY config already exists and is valid at {}",
            result.path.display()
        );
    }
    Ok(())
}

fn validate_config(path: Option<PathBuf>) -> Result<(), String> {
    let path = resolve_config_path(path)?;
    let config = load_config(&path).map_err(|error| error.to_string())?;
    println!(
        "RusTTY config valid: path={}, schema_version={}, sessions={}, tools={}",
        path.display(),
        config.schema_version,
        config.session_count(),
        config.tool_count()
    );
    Ok(())
}

fn import_known_hosts_file(
    source_path: PathBuf,
    known_hosts_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), String> {
    let destination_path = resolve_known_hosts_path(known_hosts_path)?;
    let result = import_known_hosts(&source_path, &destination_path, dry_run)
        .map_err(|error| error.to_string())?;
    let mode = if dry_run { "dry-run" } else { "import" };
    println!(
        "RusTTY known-hosts {mode}: source={}, destination={}, imported={}, already_present={}, skipped_blank_or_comment={}, skipped_marked={}, skipped_hashed={}, skipped_wildcard={}, skipped_negated={}, skipped_unsupported={}, skipped_total={}",
        result.source_path.display(),
        result.destination_path.display(),
        result.imported,
        result.already_present,
        result.skipped_blank_or_comment,
        result.skipped_marked,
        result.skipped_hashed,
        result.skipped_wildcard,
        result.skipped_negated,
        result.skipped_unsupported,
        result.skipped_total(),
    );
    Ok(())
}

fn import_putty_host_keys_file(
    source_path: PathBuf,
    known_hosts_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), String> {
    let destination_path = resolve_known_hosts_path(known_hosts_path)?;
    let result = import_putty_host_keys(&source_path, &destination_path, dry_run)
        .map_err(|error| error.to_string())?;
    let mode = if dry_run { "dry-run" } else { "import" };
    println!(
        "RusTTY PuTTY host-key {mode}: source={}, destination={}, imported={}, already_present={}, skipped_blank_or_comment={}, skipped_outside_target={}, skipped_malformed={}, skipped_unsupported_key_type={}, skipped_total={}",
        result.source_path.display(),
        result.destination_path.display(),
        result.imported,
        result.already_present,
        result.skipped_blank_or_comment,
        result.skipped_outside_target,
        result.skipped_malformed,
        result.skipped_unsupported_key_type,
        result.skipped_total(),
    );
    Ok(())
}

fn import_putty_sessions_file(
    source_path: PathBuf,
    config_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), String> {
    let destination_path = resolve_config_path(config_path)?;
    let result = import_putty_sessions(&source_path, &destination_path, dry_run)
        .map_err(|error| error.to_string())?;
    let mode = if dry_run { "dry-run" } else { "import" };
    println!(
        "RusTTY PuTTY session {mode}: source={}, destination={}, discovered_sessions={}, imported={}, already_present={}, skipped_blank_or_comment={}, skipped_outside_target={}, skipped_malformed={}, skipped_unsupported_protocol={}, skipped_unlaunchable={}, skipped_conflicting={}, skipped_total={}",
        result.source_path.display(),
        result.destination_path.display(),
        result.discovered_sessions,
        result.imported,
        result.already_present,
        result.skipped_blank_or_comment,
        result.skipped_outside_target,
        result.skipped_malformed,
        result.skipped_unsupported_protocol,
        result.skipped_unlaunchable,
        result.skipped_conflicting,
        result.skipped_total(),
    );
    Ok(())
}

fn resolve_config_path(path: Option<PathBuf>) -> Result<PathBuf, String> {
    path.map_or_else(
        || default_config_path().map_err(|error| error.to_string()),
        Ok,
    )
}

fn resolve_known_hosts_path(path: Option<PathBuf>) -> Result<PathBuf, String> {
    path.map_or_else(
        || default_known_hosts_path().map_err(|error| error.to_string()),
        Ok,
    )
}

fn consume_optional_path(arguments: &[String], index: &mut usize) -> Option<String> {
    let next_index = *index + 1;
    let raw_path = arguments.get(next_index)?;
    if raw_path.starts_with("--") {
        return None;
    }
    *index = next_index;
    Some(raw_path.clone())
}

fn set_command_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!(
            "unsupported argument combination involving {flag}\n\n{USAGE}"
        ));
    }

    *slot = Some(value);
    Ok(())
}

fn set_option_once<T>(slot: &mut Option<T>, value: T, message: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{message}\n\n{USAGE}"));
    }

    *slot = Some(value);
    Ok(())
}

fn reject_import_only_flags(
    known_hosts_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), String> {
    if known_hosts_path.is_some() {
        return Err(format!(
            "--known-hosts requires a host-key import command\n\n{USAGE}"
        ));
    }
    if config_path.is_some() {
        return Err(format!(
            "--config requires --import-putty-sessions\n\n{USAGE}"
        ));
    }
    if dry_run {
        return Err(format!("--dry-run requires an import command\n\n{USAGE}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, parse_command};

    #[test]
    fn defaults_to_gui_mode() {
        assert_eq!(parse_command(Vec::<String>::new()), Ok(Command::Gui));
    }

    #[test]
    fn parses_init_config_with_attached_path() {
        assert_eq!(
            parse_command(["--init-config=/tmp/rustty.toml".to_owned()]),
            Ok(Command::InitConfig(Some(PathBuf::from("/tmp/rustty.toml"))))
        );
    }

    #[test]
    fn parses_validate_config_with_positional_path() {
        assert_eq!(
            parse_command([
                "--validate-config".to_owned(),
                "/tmp/rustty.toml".to_owned()
            ]),
            Ok(Command::ValidateConfig(Some(PathBuf::from(
                "/tmp/rustty.toml"
            ))))
        );
    }

    #[test]
    fn parses_show_default_known_hosts_path() {
        assert_eq!(
            parse_command(["--show-default-known-hosts-path".to_owned()]),
            Ok(Command::ShowDefaultKnownHostsPath)
        );
    }

    #[test]
    fn parses_import_known_hosts_with_destination_and_dry_run() {
        assert_eq!(
            parse_command([
                "--import-known-hosts".to_owned(),
                "/tmp/known_hosts".to_owned(),
                "--known-hosts".to_owned(),
                "/tmp/rustty-known_hosts".to_owned(),
                "--dry-run".to_owned(),
            ]),
            Ok(Command::ImportKnownHosts {
                source_path: PathBuf::from("/tmp/known_hosts"),
                known_hosts_path: Some(PathBuf::from("/tmp/rustty-known_hosts")),
                dry_run: true,
            })
        );
    }

    #[test]
    fn parses_import_putty_host_keys_with_destination_and_dry_run() {
        assert_eq!(
            parse_command([
                "--import-putty-host-keys".to_owned(),
                "/tmp/putty-hostkeys.reg".to_owned(),
                "--known-hosts".to_owned(),
                "/tmp/rustty-known_hosts".to_owned(),
                "--dry-run".to_owned(),
            ]),
            Ok(Command::ImportPuttyHostKeys {
                source_path: PathBuf::from("/tmp/putty-hostkeys.reg"),
                known_hosts_path: Some(PathBuf::from("/tmp/rustty-known_hosts")),
                dry_run: true,
            })
        );
    }

    #[test]
    fn parses_import_putty_sessions_with_config_and_dry_run() {
        assert_eq!(
            parse_command([
                "--import-putty-sessions".to_owned(),
                "/tmp/putty-sessions.reg".to_owned(),
                "--config".to_owned(),
                "/tmp/rustty.toml".to_owned(),
                "--dry-run".to_owned(),
            ]),
            Ok(Command::ImportPuttySessions {
                source_path: PathBuf::from("/tmp/putty-sessions.reg"),
                config_path: Some(PathBuf::from("/tmp/rustty.toml")),
                dry_run: true,
            })
        );
    }

    #[test]
    fn rejects_known_hosts_without_import_command() {
        let error = parse_command([
            "--show-default-config-path".to_owned(),
            "--known-hosts".to_owned(),
            "/tmp/rustty-known_hosts".to_owned(),
        ])
        .expect_err("standalone known-hosts flag should fail");

        assert!(error.contains("--known-hosts requires a host-key import command"));
    }

    #[test]
    fn rejects_config_without_session_import_command() {
        let error = parse_command([
            "--show-default-config-path".to_owned(),
            "--config".to_owned(),
            "/tmp/rustty.toml".to_owned(),
        ])
        .expect_err("standalone config flag should fail");

        assert!(error.contains("--config requires --import-putty-sessions"));
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = parse_command(["--bogus".to_owned()]).expect_err("unknown flags should fail");
        assert!(error.contains("unsupported argument"));
    }
}
