use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};

use russh::keys::{self, HashAlg, PrivateKey, PublicKey, ssh_key::LineEnding};

const USAGE: &str = "\
rusttygen bootstrap CLI

Usage:
  rusttygen --help
  rusttygen --inspect PATH [--passphrase-env ENV]
  rusttygen --inspect=PATH [--passphrase-env ENV]
  rusttygen --convert PATH --output PATH [--public-output PATH] [--passphrase-env ENV]
  rusttygen --convert=PATH --output PATH [--public-output PATH] [--passphrase-env ENV]

Notes:
  `--inspect` prints line-oriented key metadata for OpenSSH or PuTTY PPK inputs.
  `--convert` currently writes an OpenSSH private key.
  `--public-output PATH` optionally writes the matching OpenSSH public key.
  `--passphrase-env ENV` reads the input-key passphrase from an environment variable.
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Inspect {
        input_path: PathBuf,
        passphrase_env: Option<String>,
    },
    Convert {
        input_path: PathBuf,
        output_path: PathBuf,
        public_output_path: Option<PathBuf>,
        passphrase_env: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyInputFormat {
    OpenSsh,
    PuttyPpk,
}

impl KeyInputFormat {
    fn label(self) -> &'static str {
        match self {
            Self::OpenSsh => "openssh_private_key",
            Self::PuttyPpk => "putty_ppk",
        }
    }
}

#[derive(Debug)]
struct LoadedKeyMaterial {
    input_format: KeyInputFormat,
    input_encrypted: bool,
    private_key: PrivateKey,
}

fn main() {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    if let Err(error) = run(std::env::args().skip(1), &mut stdout, &mut stderr) {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run<I, W, E>(arguments: I, writer: &mut W, error_writer: &mut E) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
    W: Write,
    E: Write,
{
    let _ = error_writer;
    match parse_command(arguments)? {
        Command::Help => {
            write!(writer, "{USAGE}").map_err(|error| error.to_string())?;
            Ok(())
        }
        Command::Inspect {
            input_path,
            passphrase_env,
        } => inspect_key(
            &input_path,
            resolve_secret_env(passphrase_env.as_deref())?,
            writer,
        ),
        Command::Convert {
            input_path,
            output_path,
            public_output_path,
            passphrase_env,
        } => convert_key(
            &input_path,
            &output_path,
            public_output_path.as_deref(),
            resolve_secret_env(passphrase_env.as_deref())?,
            writer,
        ),
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

    let mut inspect_path = None;
    let mut convert_path = None;
    let mut output_path = None;
    let mut public_output_path = None;
    let mut passphrase_env = None;

    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--inspect" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --inspect"))?;
                set_option_once(
                    &mut inspect_path,
                    PathBuf::from(raw_path),
                    "duplicate --inspect flag",
                )?;
                index += 1;
            }
            "--convert" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --convert"))?;
                set_option_once(
                    &mut convert_path,
                    PathBuf::from(raw_path),
                    "duplicate --convert flag",
                )?;
                index += 1;
            }
            "--output" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --output"))?;
                set_option_once(
                    &mut output_path,
                    PathBuf::from(raw_path),
                    "duplicate --output flag",
                )?;
                index += 1;
            }
            "--public-output" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --public-output"))?;
                set_option_once(
                    &mut public_output_path,
                    PathBuf::from(raw_path),
                    "duplicate --public-output flag",
                )?;
                index += 1;
            }
            "--passphrase-env" => {
                let raw_env = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --passphrase-env"))?;
                set_option_once(
                    &mut passphrase_env,
                    raw_env.clone(),
                    "duplicate --passphrase-env flag",
                )?;
                index += 1;
            }
            _ => {
                if let Some(raw_path) = argument.strip_prefix("--inspect=") {
                    set_option_once(
                        &mut inspect_path,
                        PathBuf::from(raw_path),
                        "duplicate --inspect flag",
                    )?;
                } else if let Some(raw_path) = argument.strip_prefix("--convert=") {
                    set_option_once(
                        &mut convert_path,
                        PathBuf::from(raw_path),
                        "duplicate --convert flag",
                    )?;
                } else if let Some(raw_path) = argument.strip_prefix("--output=") {
                    set_option_once(
                        &mut output_path,
                        PathBuf::from(raw_path),
                        "duplicate --output flag",
                    )?;
                } else if let Some(raw_path) = argument.strip_prefix("--public-output=") {
                    set_option_once(
                        &mut public_output_path,
                        PathBuf::from(raw_path),
                        "duplicate --public-output flag",
                    )?;
                } else if let Some(raw_env) = argument.strip_prefix("--passphrase-env=") {
                    set_option_once(
                        &mut passphrase_env,
                        raw_env.to_owned(),
                        "duplicate --passphrase-env flag",
                    )?;
                } else if matches!(argument.as_str(), "--help" | "-h") {
                    return Err(usage_error(
                        "help must be requested without other arguments",
                    ));
                } else if argument.starts_with('-') {
                    return Err(usage_error(format!("unsupported argument: {argument}")));
                } else {
                    return Err(usage_error(format!(
                        "unexpected positional argument: {argument}"
                    )));
                }
            }
        }
        index += 1;
    }

    match (inspect_path, convert_path) {
        (Some(_), Some(_)) => Err(usage_error(
            "choose exactly one primary command: --inspect or --convert",
        )),
        (None, None) => Err(usage_error("missing command: use --inspect or --convert")),
        (Some(input_path), None) => {
            if output_path.is_some() || public_output_path.is_some() {
                return Err(usage_error(
                    "--output and --public-output are only valid with --convert",
                ));
            }

            Ok(Command::Inspect {
                input_path,
                passphrase_env,
            })
        }
        (None, Some(input_path)) => {
            let output_path =
                output_path.ok_or_else(|| usage_error("--convert requires --output PATH"))?;
            Ok(Command::Convert {
                input_path,
                output_path,
                public_output_path,
                passphrase_env,
            })
        }
    }
}

fn inspect_key<W>(
    input_path: &Path,
    passphrase: Option<String>,
    writer: &mut W,
) -> Result<(), String>
where
    W: Write,
{
    let loaded_key = load_key_material(input_path, passphrase)?;
    print_key_metadata(writer, "inspect", input_path, &loaded_key, None, None)
}

fn convert_key<W>(
    input_path: &Path,
    output_path: &Path,
    public_output_path: Option<&Path>,
    passphrase: Option<String>,
    writer: &mut W,
) -> Result<(), String>
where
    W: Write,
{
    validate_output_path(output_path, "--output")?;
    if let Some(public_output_path) = public_output_path {
        validate_output_path(public_output_path, "--public-output")?;
    }

    let loaded_key = load_key_material(input_path, passphrase)?;
    ensure_parent_directory(output_path)?;
    loaded_key
        .private_key
        .write_openssh_file(output_path, LineEnding::LF)
        .map_err(|error| {
            format!(
                "failed to write OpenSSH private key {}: {error}",
                output_path.display()
            )
        })?;

    if let Some(public_output_path) = public_output_path {
        ensure_parent_directory(public_output_path)?;
        write_public_key_file(public_output_path, loaded_key.private_key.public_key())?;
    }

    print_key_metadata(
        writer,
        "convert",
        input_path,
        &loaded_key,
        Some(output_path),
        public_output_path,
    )
}

fn print_key_metadata<W>(
    writer: &mut W,
    mode: &str,
    input_path: &Path,
    loaded_key: &LoadedKeyMaterial,
    output_path: Option<&Path>,
    public_output_path: Option<&Path>,
) -> Result<(), String>
where
    W: Write,
{
    writeln!(writer, "mode={mode}").map_err(|error| error.to_string())?;
    writeln!(writer, "input_path={}", input_path.display()).map_err(|error| error.to_string())?;
    writeln!(writer, "input_format={}", loaded_key.input_format.label())
        .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "input_encrypted={}",
        render_bool(loaded_key.input_encrypted)
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "algorithm={}",
        loaded_key.private_key.algorithm().as_str()
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "comment={}",
        render_text(loaded_key.private_key.comment())
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "fingerprint_sha256={}",
        loaded_key.private_key.fingerprint(HashAlg::Sha256)
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "public_key={}",
        loaded_key
            .private_key
            .public_key()
            .to_openssh()
            .map_err(|error| format!("failed to encode OpenSSH public key: {error}"))?
    )
    .map_err(|error| error.to_string())?;
    writeln!(writer, "output_path={}", render_path(output_path))
        .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "public_output_path={}",
        render_path(public_output_path)
    )
    .map_err(|error| error.to_string())
}

fn load_key_material(
    input_path: &Path,
    passphrase: Option<String>,
) -> Result<LoadedKeyMaterial, String> {
    let secret = fs::read_to_string(input_path)
        .map_err(|error| format!("failed to read key file {}: {error}", input_path.display()))?;
    let input_format = detect_key_input_format(&secret)?;
    let input_encrypted = detect_input_encryption(&secret, input_format)?;
    let private_key = keys::decode_secret_key(&secret, passphrase.as_deref()).map_err(|error| {
        format!(
            "failed to decode {} key {}: {error}",
            input_format.label(),
            input_path.display()
        )
    })?;

    Ok(LoadedKeyMaterial {
        input_format,
        input_encrypted,
        private_key,
    })
}

fn detect_key_input_format(secret: &str) -> Result<KeyInputFormat, String> {
    let trimmed = secret.trim_start();
    if trimmed.starts_with("PuTTY-User-Key-File-") {
        return Ok(KeyInputFormat::PuttyPpk);
    }
    if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Ok(KeyInputFormat::OpenSsh);
    }

    Err("unsupported key format; rusttygen currently accepts PuTTY PPK and OpenSSH private-key files".to_owned())
}

fn detect_input_encryption(secret: &str, input_format: KeyInputFormat) -> Result<bool, String> {
    match input_format {
        KeyInputFormat::PuttyPpk => {
            let encryption = secret
                .lines()
                .find_map(|line| line.strip_prefix("Encryption:"))
                .map(str::trim)
                .ok_or_else(|| "PPK file is missing an Encryption header".to_owned())?;
            Ok(!matches!(encryption, "none" | "None"))
        }
        KeyInputFormat::OpenSsh => PrivateKey::from_openssh(secret)
            .map(|private_key| private_key.is_encrypted())
            .map_err(|error| {
                format!("failed to inspect OpenSSH private-key encryption state: {error}")
            }),
    }
}

fn write_public_key_file(path: &Path, public_key: &PublicKey) -> Result<(), String> {
    let encoded = public_key
        .to_openssh()
        .map_err(|error| format!("failed to encode OpenSSH public key: {error}"))?;
    fs::write(path, format!("{encoded}\n")).map_err(|error| {
        format!(
            "failed to write OpenSSH public key {}: {error}",
            path.display()
        )
    })
}

fn ensure_parent_directory(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create directory {}: {error}", parent.display()))
}

fn resolve_secret_env(passphrase_env: Option<&str>) -> Result<Option<String>, String> {
    match passphrase_env {
        None => Ok(None),
        Some(name) if name.trim().is_empty() => {
            Err("passphrase environment variable name must not be empty".to_owned())
        }
        Some(name) => std::env::var(name)
            .map(Some)
            .map_err(|_| format!("missing passphrase in environment variable {name}")),
    }
}

fn validate_output_path(path: &Path, flag: &str) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(format!("{flag} path must not be empty"));
    }

    Ok(())
}

fn render_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn render_text(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn render_path(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_owned())
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

    use super::{Command, detect_key_input_format, load_key_material, parse_command, run};

    const PPK_FIXTURE: &str = include_str!("../../../tests/fixtures/keys/id_ed25519.ppk");
    const ENCRYPTED_PPK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/keys/id_ed25519_enc.ppk");

    #[test]
    fn defaults_to_help_when_no_arguments_are_supplied() {
        assert_eq!(parse_command(Vec::<String>::new()), Ok(Command::Help));
    }

    #[test]
    fn parses_convert_with_public_output() {
        assert_eq!(
            parse_command([
                "--convert".to_owned(),
                "/tmp/id_ed25519.ppk".to_owned(),
                "--output".to_owned(),
                "/tmp/id_rustty".to_owned(),
                "--public-output=/tmp/id_rustty.pub".to_owned(),
            ]),
            Ok(Command::Convert {
                input_path: PathBuf::from("/tmp/id_ed25519.ppk"),
                output_path: PathBuf::from("/tmp/id_rustty"),
                public_output_path: Some(PathBuf::from("/tmp/id_rustty.pub")),
                passphrase_env: None,
            })
        );
    }

    #[test]
    fn detects_putty_ppk_input_format() {
        assert_eq!(
            detect_key_input_format(PPK_FIXTURE).expect("fixture format should be detected"),
            super::KeyInputFormat::PuttyPpk
        );
    }

    #[test]
    fn inspect_reports_putty_ppk_metadata() {
        let workspace = temporary_workspace();
        let input_path = workspace.join("id_ed25519.ppk");
        std::fs::write(&input_path, PPK_FIXTURE).expect("fixture should be written");

        let mut output = Vec::new();
        let mut error_output = Vec::new();
        run(
            ["--inspect".to_owned(), input_path.display().to_string()],
            &mut output,
            &mut error_output,
        )
        .expect("inspect command should succeed");

        let output = String::from_utf8(output).expect("output should be UTF-8");
        assert!(output.contains("mode=inspect"));
        assert!(output.contains("input_format=putty_ppk"));
        assert!(output.contains("input_encrypted=no"));
        assert!(output.contains("algorithm=ssh-ed25519"));
        assert!(output.contains("comment=user@example.com"));
        assert!(output.contains("fingerprint_sha256=SHA256:"));
        assert!(output.contains("public_key=ssh-ed25519 "));
        assert!(output.contains("output_path=-"));
        assert!(error_output.is_empty());
    }

    #[test]
    fn load_key_material_supports_encrypted_putty_ppk() {
        let workspace = temporary_workspace();
        let input_path = workspace.join("id_ed25519_enc.ppk");
        std::fs::write(&input_path, ENCRYPTED_PPK_FIXTURE).expect("fixture should be written");

        let loaded_key = load_key_material(&input_path, Some("123".to_owned()))
            .expect("encrypted PPK should load");
        assert_eq!(loaded_key.input_format, super::KeyInputFormat::PuttyPpk);
        assert!(loaded_key.input_encrypted);
        assert_eq!(loaded_key.private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(loaded_key.private_key.comment(), "user@example.com");
    }

    #[test]
    fn convert_writes_openssh_private_and_public_keys() {
        let workspace = temporary_workspace();
        let input_path = workspace.join("id_ed25519.ppk");
        let output_path = workspace.join("converted").join("id_ed25519");
        let public_output_path = workspace.join("converted").join("id_ed25519.pub");
        std::fs::write(&input_path, PPK_FIXTURE).expect("fixture should be written");

        let mut output = Vec::new();
        let mut error_output = Vec::new();
        run(
            [
                "--convert".to_owned(),
                input_path.display().to_string(),
                "--output".to_owned(),
                output_path.display().to_string(),
                "--public-output".to_owned(),
                public_output_path.display().to_string(),
            ],
            &mut output,
            &mut error_output,
        )
        .expect("convert command should succeed");

        let private_key =
            std::fs::read_to_string(&output_path).expect("converted private key should be written");
        let public_key = std::fs::read_to_string(&public_output_path)
            .expect("converted public key should be written");
        assert!(private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(public_key.starts_with("ssh-ed25519 "));

        let output = String::from_utf8(output).expect("output should be UTF-8");
        assert!(output.contains("mode=convert"));
        assert!(output.contains("input_format=putty_ppk"));
        assert!(output.contains(&format!("output_path={}", output_path.display())));
        assert!(output.contains(&format!(
            "public_output_path={}",
            public_output_path.display()
        )));
        assert!(error_output.is_empty());
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rusttygen-cli-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
