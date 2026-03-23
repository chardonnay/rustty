use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process,
};

#[cfg(unix)]
use std::{future::Future, path::Path, time::Duration};

#[cfg(unix)]
use russh::keys::{
    HashAlg, PrivateKey, agent::Constraint, agent::client::AgentClient, agent::server,
    load_secret_key,
};
use rustty_config::default_agent_socket_path;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;

const USAGE: &str = "\
rusagent bootstrap CLI

Usage:
  rusagent --help
  rusagent --show-default-socket-path
  rusagent --list [--socket PATH]
  rusagent --add-identity PATH [--socket PATH] [--passphrase-env ENV] [--lifetime SECONDS]
  rusagent --serve [--socket PATH] [--identity PATH]... [--passphrase-env ENV] [--lifetime SECONDS]
  rusagent --serve [--socket=PATH] [--identity=PATH]... [--passphrase-env=ENV] [--lifetime=SECONDS]

Notes:
  `--serve` runs in the foreground until interrupted.
  `--identity PATH` preloads one or more OpenSSH or PuTTY PPK private keys into the agent.
  `--passphrase-env ENV` is used for encrypted private keys during add/load.
  `--lifetime SECONDS` applies an SSH-agent lifetime constraint to loaded keys.
";

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    ShowDefaultSocketPath,
    List {
        socket_path: Option<PathBuf>,
    },
    AddIdentity {
        socket_path: Option<PathBuf>,
        identity_path: PathBuf,
        passphrase_env: Option<String>,
        lifetime_seconds: Option<u32>,
    },
    Serve {
        socket_path: Option<PathBuf>,
        identity_paths: Vec<PathBuf>,
        passphrase_env: Option<String>,
        lifetime_seconds: Option<u32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdentityLoadSpec {
    path: PathBuf,
    passphrase_env: Option<String>,
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
    match parse_command(arguments)? {
        Command::Help => {
            write!(writer, "{USAGE}").map_err(|error| error.to_string())?;
            Ok(())
        }
        Command::ShowDefaultSocketPath => show_default_socket_path(writer),
        Command::List { socket_path } => list_identities(socket_path, writer),
        Command::AddIdentity {
            socket_path,
            identity_path,
            passphrase_env,
            lifetime_seconds,
        } => add_identity(
            socket_path,
            identity_path,
            passphrase_env,
            lifetime_seconds,
            writer,
        ),
        Command::Serve {
            socket_path,
            identity_paths,
            passphrase_env,
            lifetime_seconds,
        } => serve_agent(
            socket_path,
            identity_paths,
            passphrase_env,
            lifetime_seconds,
            writer,
            error_writer,
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

    let mut show_default_socket_path = false;
    let mut list = false;
    let mut serve = false;
    let mut add_identity_path = None;
    let mut identity_paths = Vec::new();
    let mut socket_path = None;
    let mut passphrase_env = None;
    let mut lifetime_seconds = None;

    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--show-default-socket-path" => {
                show_default_socket_path = true;
            }
            "--list" => {
                list = true;
            }
            "--serve" => {
                serve = true;
            }
            "--socket" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --socket"))?;
                set_option_once(
                    &mut socket_path,
                    PathBuf::from(raw_path),
                    "duplicate --socket flag",
                )?;
                index += 1;
            }
            "--identity" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --identity"))?;
                identity_paths.push(PathBuf::from(raw_path));
                index += 1;
            }
            "--add-identity" => {
                let raw_path = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --add-identity"))?;
                set_option_once(
                    &mut add_identity_path,
                    PathBuf::from(raw_path),
                    "duplicate --add-identity flag",
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
            "--lifetime" => {
                let raw_seconds = arguments
                    .get(index + 1)
                    .ok_or_else(|| usage_error("missing value for --lifetime"))?;
                let seconds = parse_lifetime(raw_seconds)?;
                set_option_once(&mut lifetime_seconds, seconds, "duplicate --lifetime flag")?;
                index += 1;
            }
            _ => {
                if let Some(raw_path) = argument.strip_prefix("--socket=") {
                    set_option_once(
                        &mut socket_path,
                        PathBuf::from(raw_path),
                        "duplicate --socket flag",
                    )?;
                } else if let Some(raw_path) = argument.strip_prefix("--identity=") {
                    identity_paths.push(PathBuf::from(raw_path));
                } else if let Some(raw_path) = argument.strip_prefix("--add-identity=") {
                    set_option_once(
                        &mut add_identity_path,
                        PathBuf::from(raw_path),
                        "duplicate --add-identity flag",
                    )?;
                } else if let Some(raw_env) = argument.strip_prefix("--passphrase-env=") {
                    set_option_once(
                        &mut passphrase_env,
                        raw_env.to_owned(),
                        "duplicate --passphrase-env flag",
                    )?;
                } else if let Some(raw_seconds) = argument.strip_prefix("--lifetime=") {
                    let seconds = parse_lifetime(raw_seconds)?;
                    set_option_once(&mut lifetime_seconds, seconds, "duplicate --lifetime flag")?;
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

    if show_default_socket_path {
        if list
            || serve
            || add_identity_path.is_some()
            || socket_path.is_some()
            || passphrase_env.is_some()
            || lifetime_seconds.is_some()
            || !identity_paths.is_empty()
        {
            return Err(usage_error(
                "--show-default-socket-path does not accept additional arguments",
            ));
        }
        return Ok(Command::ShowDefaultSocketPath);
    }

    if list {
        if serve
            || add_identity_path.is_some()
            || passphrase_env.is_some()
            || lifetime_seconds.is_some()
            || !identity_paths.is_empty()
        {
            return Err(usage_error(
                "--list cannot be combined with serve or key-loading arguments",
            ));
        }
        return Ok(Command::List { socket_path });
    }

    if let Some(identity_path) = add_identity_path {
        if serve || !identity_paths.is_empty() {
            return Err(usage_error(
                "--add-identity cannot be combined with --serve or --identity",
            ));
        }
        return Ok(Command::AddIdentity {
            socket_path,
            identity_path,
            passphrase_env,
            lifetime_seconds,
        });
    }

    if serve {
        return Ok(Command::Serve {
            socket_path,
            identity_paths,
            passphrase_env,
            lifetime_seconds,
        });
    }

    Err(usage_error("missing rusagent command"))
}

fn show_default_socket_path<W>(writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    let path = default_agent_socket_path().map_err(|error| error.to_string())?;
    writeln!(writer, "{}", path.display()).map_err(|error| error.to_string())
}

fn list_identities<W>(socket_path: Option<PathBuf>, writer: &mut W) -> Result<(), String>
where
    W: Write,
{
    #[cfg(not(unix))]
    {
        let _ = socket_path;
        let _ = writer;
        return Err(
            "rusagent only supports Unix-domain sockets in this bootstrap slice".to_owned(),
        );
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(socket_path)?;
        let identities = runtime()?
            .block_on(async { request_identities(&socket_path).await })
            .map_err(|error| format!("rusagent agent query failed: {error}"))?;

        writeln!(writer, "socket_path={}", socket_path.display())
            .map_err(|error| error.to_string())?;
        writeln!(writer, "algorithm\tfingerprint\tcomment").map_err(|error| error.to_string())?;
        for identity in identities {
            writeln!(
                writer,
                "{}\t{}\t{}",
                identity.algorithm(),
                identity.fingerprint(HashAlg::Sha256),
                render_comment(identity.comment())
            )
            .map_err(|error| error.to_string())?;
        }

        Ok(())
    }
}

fn add_identity<W>(
    socket_path: Option<PathBuf>,
    identity_path: PathBuf,
    passphrase_env: Option<String>,
    lifetime_seconds: Option<u32>,
    writer: &mut W,
) -> Result<(), String>
where
    W: Write,
{
    #[cfg(not(unix))]
    {
        let _ = socket_path;
        let _ = identity_path;
        let _ = passphrase_env;
        let _ = lifetime_seconds;
        let _ = writer;
        return Err(
            "rusagent only supports Unix-domain sockets in this bootstrap slice".to_owned(),
        );
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(socket_path)?;
        let identity = IdentityLoadSpec {
            path: identity_path,
            passphrase_env,
        };
        runtime()?
            .block_on(async {
                add_identities_to_socket(
                    &socket_path,
                    std::slice::from_ref(&identity),
                    lifetime_seconds,
                )
                .await
            })
            .map_err(|error| format!("rusagent failed to add identity: {error}"))?;
        writeln!(writer, "socket_path={}", socket_path.display())
            .map_err(|error| error.to_string())?;
        writeln!(writer, "added_identity={}", identity.path.display())
            .map_err(|error| error.to_string())
    }
}

fn serve_agent<W, E>(
    socket_path: Option<PathBuf>,
    identity_paths: Vec<PathBuf>,
    passphrase_env: Option<String>,
    lifetime_seconds: Option<u32>,
    writer: &mut W,
    error_writer: &mut E,
) -> Result<(), String>
where
    W: Write,
    E: Write,
{
    #[cfg(not(unix))]
    {
        let _ = socket_path;
        let _ = identity_paths;
        let _ = passphrase_env;
        let _ = lifetime_seconds;
        let _ = writer;
        let _ = error_writer;
        return Err(
            "rusagent only supports Unix-domain sockets in this bootstrap slice".to_owned(),
        );
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(socket_path)?;
        let identities = identity_paths
            .into_iter()
            .map(|path| IdentityLoadSpec {
                path,
                passphrase_env: passphrase_env.clone(),
            })
            .collect::<Vec<_>>();

        writeln!(writer, "socket_path={}", socket_path.display())
            .map_err(|error| error.to_string())?;
        writeln!(
            error_writer,
            "rusagent: serving SSH agent on {}; press Ctrl-C to stop",
            socket_path.display()
        )
        .map_err(|error| error.to_string())?;

        runtime()?.block_on(async {
            serve_agent_until(
                socket_path,
                identities,
                lifetime_seconds,
                tokio::signal::ctrl_c(),
            )
            .await
        })
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start Tokio runtime: {error}"))
}

fn resolve_socket_path(socket_path: Option<PathBuf>) -> Result<PathBuf, String> {
    socket_path.map_or_else(
        || default_agent_socket_path().map_err(|error| error.to_string()),
        |path| {
            if path.as_os_str().is_empty() {
                Err("SSH-agent socket path must not be empty".to_owned())
            } else {
                Ok(path)
            }
        },
    )
}

fn parse_lifetime(raw_seconds: &str) -> Result<u32, String> {
    raw_seconds
        .parse::<u32>()
        .map_err(|_| usage_error(format!("invalid lifetime value: {raw_seconds}")))
}

fn resolve_secret_env(env_var: &str, secret_label: &str) -> Result<String, String> {
    let value = env::var(env_var)
        .map_err(|_| format!("missing {secret_label} in environment variable {env_var}"))?;
    if value.is_empty() {
        return Err(format!(
            "{secret_label} environment variable {env_var} must not be empty"
        ));
    }

    Ok(value)
}

fn render_comment(comment: &str) -> &str {
    if comment.is_empty() { "-" } else { comment }
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

#[cfg(unix)]
async fn serve_agent_until<F>(
    socket_path: PathBuf,
    identities: Vec<IdentityLoadSpec>,
    lifetime_seconds: Option<u32>,
    shutdown: F,
) -> Result<(), String>
where
    F: Future<Output = io::Result<()>>,
{
    create_parent_directory(&socket_path)?;
    remove_stale_socket(&socket_path)?;
    let _cleanup = SocketCleanup::new(socket_path.clone());

    let listener = UnixListener::bind(&socket_path).map_err(|error| {
        format!(
            "failed to bind agent socket {}: {error}",
            socket_path.display()
        )
    })?;
    let mut server_task =
        tokio::spawn(async move { server::serve(UnixListenerStream::new(listener), ()).await });

    wait_for_agent_socket(&socket_path).await?;
    if !identities.is_empty() {
        add_identities_to_socket(&socket_path, &identities, lifetime_seconds).await?;
    }

    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut server_task => match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("rusagent server exited with an error: {error}")),
            Err(error) => Err(format!("rusagent server task failed: {error}")),
        },
        shutdown_result = &mut shutdown => {
            if let Err(error) = shutdown_result {
                return Err(format!("rusagent shutdown listener failed: {error}"));
            }
            server_task.abort();
            let _ = server_task.await;
            Ok(())
        }
    }
}

#[cfg(unix)]
async fn add_identities_to_socket(
    socket_path: &Path,
    identities: &[IdentityLoadSpec],
    lifetime_seconds: Option<u32>,
) -> Result<(), String> {
    let mut client = AgentClient::connect_uds(socket_path)
        .await
        .map_err(|error| {
            format!(
                "failed to connect to rusagent socket {}: {error}",
                socket_path.display()
            )
        })?;
    let constraints = agent_constraints(lifetime_seconds);

    for identity in identities {
        let private_key = load_identity(identity)?;
        client
            .add_identity(&private_key, &constraints)
            .await
            .map_err(|error| {
                format!(
                    "failed to add identity {} to rusagent: {error}",
                    identity.path.display()
                )
            })?;
    }

    Ok(())
}

#[cfg(unix)]
async fn request_identities(socket_path: &Path) -> Result<Vec<russh::keys::PublicKey>, String> {
    let mut client = AgentClient::connect_uds(socket_path)
        .await
        .map_err(|error| {
            format!(
                "failed to connect to rusagent socket {}: {error}",
                socket_path.display()
            )
        })?;
    client
        .request_identities()
        .await
        .map_err(|error| format!("failed to request identities from rusagent: {error}"))
}

#[cfg(unix)]
fn agent_constraints(lifetime_seconds: Option<u32>) -> Vec<Constraint> {
    lifetime_seconds
        .map(|seconds| vec![Constraint::KeyLifetime { seconds }])
        .unwrap_or_default()
}

#[cfg(unix)]
fn load_identity(identity: &IdentityLoadSpec) -> Result<PrivateKey, String> {
    let passphrase = identity
        .passphrase_env
        .as_deref()
        .map(|env_var| resolve_secret_env(env_var, "SSH key passphrase"))
        .transpose()?;

    load_identity_with_passphrase(&identity.path, passphrase.as_deref())
}

#[cfg(unix)]
fn load_identity_with_passphrase(
    identity_path: &Path,
    passphrase: Option<&str>,
) -> Result<PrivateKey, String> {
    load_secret_key(identity_path, passphrase).map_err(|error| {
        format!(
            "failed to load SSH private key {}: {error}",
            identity_path.display()
        )
    })
}

#[cfg(unix)]
fn create_parent_directory(socket_path: &Path) -> Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Err(format!(
            "agent socket path {} does not have a parent directory",
            socket_path.display()
        ));
    };

    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create agent directory {}: {error}",
            parent.display()
        )
    })
}

#[cfg(unix)]
fn remove_stale_socket(socket_path: &Path) -> Result<(), String> {
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove existing agent socket {}: {error}",
            socket_path.display()
        )),
    }
}

#[cfg(unix)]
async fn wait_for_agent_socket(socket_path: &Path) -> Result<(), String> {
    let mut last_error = None;
    for _ in 0..50 {
        match AgentClient::connect_uds(socket_path).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    Err(format!(
        "agent socket {} did not become ready: {}",
        socket_path.display(),
        last_error.unwrap_or_else(|| "unknown error".to_owned())
    ))
}

#[cfg(unix)]
struct SocketCleanup {
    path: PathBuf,
}

#[cfg(unix)]
impl SocketCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, parse_command, run};

    #[test]
    fn defaults_to_help_when_no_arguments_are_supplied() {
        assert_eq!(parse_command(Vec::<String>::new()), Ok(Command::Help));
    }

    #[test]
    fn parses_list_with_attached_socket_path() {
        assert_eq!(
            parse_command([
                "--list".to_owned(),
                "--socket=/tmp/rusagent.sock".to_owned()
            ]),
            Ok(Command::List {
                socket_path: Some(PathBuf::from("/tmp/rusagent.sock")),
            })
        );
    }

    #[test]
    fn parses_add_identity_with_lifetime() {
        assert_eq!(
            parse_command([
                "--add-identity".to_owned(),
                "/tmp/id_ed25519".to_owned(),
                "--socket".to_owned(),
                "/tmp/rusagent.sock".to_owned(),
                "--passphrase-env".to_owned(),
                "RUSTTY_AGENT_KEY_PASSPHRASE".to_owned(),
                "--lifetime".to_owned(),
                "60".to_owned(),
            ]),
            Ok(Command::AddIdentity {
                socket_path: Some(PathBuf::from("/tmp/rusagent.sock")),
                identity_path: PathBuf::from("/tmp/id_ed25519"),
                passphrase_env: Some("RUSTTY_AGENT_KEY_PASSPHRASE".to_owned()),
                lifetime_seconds: Some(60),
            })
        );
    }

    #[test]
    fn show_default_socket_path_runs() {
        let mut output = Vec::new();
        let mut error_output = Vec::new();
        run(
            ["--show-default-socket-path".to_owned()],
            &mut output,
            &mut error_output,
        )
        .expect("default socket path command should succeed");

        let output = String::from_utf8(output).expect("output should be UTF-8");
        assert!(!output.trim().is_empty());
        assert!(error_output.is_empty());
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::{
        io,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use russh::keys::Algorithm;
    use ssh_key::LineEnding;
    use ssh_key::rand_core::OsRng;
    use tokio::sync::oneshot;

    use super::load_identity_with_passphrase;

    const PPK_FIXTURE: &str = include_str!("../../../tests/fixtures/keys/id_ed25519.ppk");
    const ENCRYPTED_PPK_FIXTURE: &str =
        include_str!("../../../tests/fixtures/keys/id_ed25519_enc.ppk");

    #[test]
    fn load_identity_supports_putty_ppk_files() {
        let workspace = temporary_workspace();
        let identity_path = workspace.join("id_ed25519.ppk");
        std::fs::write(&identity_path, PPK_FIXTURE).expect("fixture should be written");

        let private_key =
            load_identity_with_passphrase(&identity_path, None).expect("PPK identity should load");
        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(private_key.comment(), "user@example.com");
    }

    #[test]
    fn load_identity_supports_encrypted_putty_ppk_files() {
        let workspace = temporary_workspace();
        let identity_path = workspace.join("id_ed25519_enc.ppk");
        std::fs::write(&identity_path, ENCRYPTED_PPK_FIXTURE).expect("fixture should be written");

        let private_key = load_identity_with_passphrase(&identity_path, Some("123"))
            .expect("encrypted PPK identity should load");
        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(private_key.comment(), "user@example.com");
    }

    #[test]
    fn serve_add_and_list_identities_round_trip() {
        let workspace = temporary_workspace();
        let socket_path = workspace.join("agent.sock");
        let identity_path = workspace.join("id_ed25519");
        let private_key = russh::keys::PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("test key should generate");
        private_key
            .write_openssh_file(&identity_path, LineEnding::LF)
            .expect("test key should be written");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime should build");

        runtime.block_on(async {
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let serve_task = tokio::spawn(super::serve_agent_until(
                socket_path.clone(),
                Vec::new(),
                None,
                async move {
                    shutdown_rx
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))
                },
            ));

            super::wait_for_agent_socket(&socket_path)
                .await
                .expect("socket should become ready");
            super::add_identities_to_socket(
                &socket_path,
                &[super::IdentityLoadSpec {
                    path: identity_path.clone(),
                    passphrase_env: None,
                }],
                Some(30),
            )
            .await
            .expect("identity should load");

            let identities = super::request_identities(&socket_path)
                .await
                .expect("identity list should load");
            assert_eq!(identities.len(), 1);

            shutdown_tx
                .send(())
                .expect("shutdown signal should be sent");
            serve_task
                .await
                .expect("serve task should finish")
                .expect("serve task should exit cleanly");
        });
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rusagent-cli-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
