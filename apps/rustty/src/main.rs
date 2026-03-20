use std::{path::PathBuf, process::ExitCode};

use rustty_config::{AppConfig, default_config_path, init_config, load_config};

const USAGE: &str = "\
RusTTY bootstrap CLI

Usage:
  rustty
  rustty --help
  rustty --print-sample-config
  rustty --show-default-config-path
  rustty --init-config [PATH]
  rustty --init-config=PATH
  rustty --validate-config [PATH]
  rustty --validate-config=PATH
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Placeholder,
    Help,
    PrintSampleConfig,
    ShowDefaultConfigPath,
    InitConfig(Option<PathBuf>),
    ValidateConfig(Option<PathBuf>),
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
        Command::Placeholder => {
            let window = rustty_ui::placeholder_window(rustty_core::tool_spec(
                rustty_core::ToolKind::Rustty,
            ));
            println!("{}\n\n{}", window.title, window.body);
            Ok(())
        }
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::PrintSampleConfig => print_sample_config(),
        Command::ShowDefaultConfigPath => show_default_config_path(),
        Command::InitConfig(path) => initialize_config(path),
        Command::ValidateConfig(path) => validate_config(path),
    }
}

fn parse_command<I>(arguments: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => Ok(Command::Placeholder),
        [single] if matches!(single.as_str(), "--help" | "-h") => Ok(Command::Help),
        [single] if single == "--print-sample-config" => Ok(Command::PrintSampleConfig),
        [single] if single == "--show-default-config-path" => Ok(Command::ShowDefaultConfigPath),
        [single] if single == "--init-config" => Ok(Command::InitConfig(None)),
        [flag, path] if flag == "--init-config" => {
            Ok(Command::InitConfig(Some(PathBuf::from(path))))
        }
        [single] if single == "--validate-config" => Ok(Command::ValidateConfig(None)),
        [flag, path] if flag == "--validate-config" => {
            Ok(Command::ValidateConfig(Some(PathBuf::from(path))))
        }
        [single] => {
            if let Some(path) = single.strip_prefix("--init-config=") {
                return Ok(Command::InitConfig(Some(PathBuf::from(path))));
            }
            if let Some(path) = single.strip_prefix("--validate-config=") {
                return Ok(Command::ValidateConfig(Some(PathBuf::from(path))));
            }
            Err(format!("unsupported argument: {single}\n\n{USAGE}"))
        }
        _ => Err(format!("unsupported argument combination\n\n{USAGE}")),
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

fn resolve_config_path(path: Option<PathBuf>) -> Result<PathBuf, String> {
    path.map_or_else(
        || default_config_path().map_err(|error| error.to_string()),
        Ok,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, parse_command};

    #[test]
    fn defaults_to_placeholder_mode() {
        assert_eq!(
            parse_command(Vec::<String>::new()),
            Ok(Command::Placeholder)
        );
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
    fn rejects_unknown_arguments() {
        let error = parse_command(["--bogus".to_owned()]).expect_err("unknown flags should fail");
        assert!(error.contains("unsupported argument"));
    }
}
