//! PuTTY session import helpers for RusTTY.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use rustty_core::{HostKeyPolicy, Protocol, SessionConfig, StorageFormat};

use crate::{
    AppConfig, ConfigError, ImportSource, StoredSession,
    store::{load_config, save_config},
    text::read_text_with_bom,
};

const PUTTY_SESSION_SECTION_PREFIX: &str =
    "[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\";

/// Summary of importing PuTTY sessions into a RusTTY config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPuttySessionsResult {
    /// Imported source path.
    pub source_path: PathBuf,
    /// RusTTY config path that receives imported sessions.
    pub destination_path: PathBuf,
    /// PuTTY sessions discovered in the source.
    pub discovered_sessions: usize,
    /// Sessions newly added to the target config.
    pub imported: usize,
    /// Sessions already present in the target config with identical normalized data.
    pub already_present: usize,
    /// Blank or comment lines skipped while scanning source files.
    pub skipped_blank_or_comment: usize,
    /// Registry-export lines outside PuTTY session sections.
    pub skipped_outside_target: usize,
    /// Malformed source lines or records skipped during import.
    pub skipped_malformed: usize,
    /// Sessions skipped because their protocol is not supported by RusTTY yet.
    pub skipped_unsupported_protocol: usize,
    /// Sessions skipped because they still lack a launchable target after normalization.
    pub skipped_unlaunchable: usize,
    /// Sessions skipped because the destination config already contains a different session with the same name.
    pub skipped_conflicting: usize,
}

impl ImportPuttySessionsResult {
    /// Total number of skipped lines or sessions in the import report.
    pub fn skipped_total(&self) -> usize {
        self.skipped_blank_or_comment
            + self.skipped_outside_target
            + self.skipped_malformed
            + self.skipped_unsupported_protocol
            + self.skipped_unlaunchable
            + self.skipped_conflicting
    }
}

/// Imports PuTTY sessions from a registry export, Unix session file, or
/// `sessions/` directory into a RusTTY config file.
pub fn import_putty_sessions(
    source_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    dry_run: bool,
) -> Result<ImportPuttySessionsResult, ConfigError> {
    let source_path = source_path.as_ref().to_path_buf();
    let destination_path = destination_path.as_ref().to_path_buf();
    let mut result = ImportPuttySessionsResult {
        source_path: source_path.clone(),
        destination_path: destination_path.clone(),
        discovered_sessions: 0,
        imported: 0,
        already_present: 0,
        skipped_blank_or_comment: 0,
        skipped_outside_target: 0,
        skipped_malformed: 0,
        skipped_unsupported_protocol: 0,
        skipped_unlaunchable: 0,
        skipped_conflicting: 0,
    };

    let mut config = if destination_path.exists() {
        load_config(&destination_path)?
    } else {
        AppConfig::empty()
    };

    let metadata = fs::metadata(&source_path).map_err(|source| ConfigError::Io {
        path: source_path.clone(),
        source,
    })?;

    if metadata.is_dir() {
        import_putty_session_directory(&source_path, &mut config, dry_run, &mut result)?;
    } else {
        let input = read_text_with_bom(&source_path)?;
        if looks_like_registry_export(&input) {
            import_putty_registry_export(&source_path, &input, &mut config, dry_run, &mut result)?;
        } else {
            import_putty_session_file(&source_path, &input, &mut config, dry_run, &mut result)?;
        }
    }

    if !dry_run && result.imported > 0 {
        save_config(&destination_path, &config)?;
    }

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPuttySession {
    name: String,
    imported_from: ImportSource,
    settings: BTreeMap<String, PuttySettingValue>,
}

impl RawPuttySession {
    fn new(name: String, imported_from: ImportSource) -> Self {
        Self {
            name,
            imported_from,
            settings: BTreeMap::new(),
        }
    }

    fn string(&self, key: &str) -> Option<&str> {
        match self.settings.get(key) {
            Some(PuttySettingValue::String(value)) => Some(value.as_str()),
            Some(PuttySettingValue::Dword(_)) | None => None,
        }
    }

    fn non_empty_string(&self, key: &str) -> Option<&str> {
        self.string(key).filter(|value| !value.is_empty())
    }

    fn int(&self, key: &str) -> Option<i64> {
        self.settings.get(key).and_then(PuttySettingValue::as_i64)
    }

    fn bool(&self, key: &str) -> Option<bool> {
        self.settings.get(key).and_then(PuttySettingValue::as_bool)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PuttySettingValue {
    String(String),
    Dword(u32),
}

impl PuttySettingValue {
    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::String(value) => value.parse::<i64>().ok(),
            Self::Dword(value) => Some(i64::from(*value)),
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::String(value) => match value {
                value if value == "0" => Some(false),
                value if value == "1" => Some(true),
                value if value.eq_ignore_ascii_case("false") => Some(false),
                value if value.eq_ignore_ascii_case("true") => Some(true),
                _ => None,
            },
            Self::Dword(value) => Some(*value != 0),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SessionImportSkip {
    Malformed,
    UnsupportedProtocol,
    Unlaunchable,
}

fn import_putty_session_directory(
    source_dir: &Path,
    config: &mut AppConfig,
    _dry_run: bool,
    result: &mut ImportPuttySessionsResult,
) -> Result<(), ConfigError> {
    let mut entries = fs::read_dir(source_dir)
        .map_err(|source| ConfigError::Io {
            path: source_dir.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ConfigError::Io {
            path: source_dir.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let entry_path = entry.path();
        let file_type = entry.file_type().map_err(|source| ConfigError::Io {
            path: entry_path.clone(),
            source,
        })?;
        if !file_type.is_file() {
            continue;
        }

        let input = read_text_with_bom(&entry_path)?;
        import_putty_session_file(&entry_path, &input, config, false, result)?;
    }

    Ok(())
}

fn import_putty_session_file(
    source_path: &Path,
    input: &str,
    config: &mut AppConfig,
    _dry_run: bool,
    result: &mut ImportPuttySessionsResult,
) -> Result<(), ConfigError> {
    let session_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigError::Io {
            path: source_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PuTTY session file name is not valid UTF-8",
            ),
        })?;
    let session_name = decode_putty_percent_escapes(session_name).map_err(|_| ConfigError::Io {
        path: source_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PuTTY session file name contains invalid escapes",
        ),
    })?;

    result.discovered_sessions += 1;
    let mut session = RawPuttySession::new(session_name, ImportSource::PuttySessionFile);

    for raw_line in input.lines() {
        let trimmed = raw_line.trim_end();
        if is_blank_or_comment_line(trimmed) {
            result.skipped_blank_or_comment += 1;
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            result.skipped_malformed += 1;
            continue;
        };
        session
            .settings
            .insert(key.to_owned(), PuttySettingValue::String(value.to_owned()));
    }

    merge_raw_putty_session(session, config, result);
    Ok(())
}

fn import_putty_registry_export(
    source_path: &Path,
    input: &str,
    config: &mut AppConfig,
    _dry_run: bool,
    result: &mut ImportPuttySessionsResult,
) -> Result<(), ConfigError> {
    let mut current_session = None::<RawPuttySession>;

    for raw_line in input.lines() {
        let trimmed = raw_line.trim();
        if is_blank_or_comment_line(trimmed) {
            result.skipped_blank_or_comment += 1;
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Some(session) = current_session.take() {
                merge_raw_putty_session(session, config, result);
            }

            if let Some(session_name) = parse_putty_registry_session_section(trimmed) {
                result.discovered_sessions += 1;
                current_session = Some(RawPuttySession::new(
                    session_name,
                    ImportSource::PuttyRegistry,
                ));
            } else {
                current_session = None;
                result.skipped_outside_target += 1;
            }
            continue;
        }

        let Some(session) = current_session.as_mut() else {
            result.skipped_outside_target += 1;
            continue;
        };

        let Some((key, value)) = parse_putty_registry_setting(trimmed) else {
            result.skipped_malformed += 1;
            continue;
        };
        session.settings.insert(key, value);
    }

    if let Some(session) = current_session.take() {
        merge_raw_putty_session(session, config, result);
    }

    if result.discovered_sessions == 0 && looks_like_registry_export(input) {
        let _ = source_path;
    }

    Ok(())
}

fn merge_raw_putty_session(
    raw_session: RawPuttySession,
    config: &mut AppConfig,
    result: &mut ImportPuttySessionsResult,
) {
    let imported_session = match normalize_putty_session(raw_session) {
        Ok(stored_session) => stored_session,
        Err(SessionImportSkip::Malformed) => {
            result.skipped_malformed += 1;
            return;
        }
        Err(SessionImportSkip::UnsupportedProtocol) => {
            result.skipped_unsupported_protocol += 1;
            return;
        }
        Err(SessionImportSkip::Unlaunchable) => {
            result.skipped_unlaunchable += 1;
            return;
        }
    };

    let existing_index = config
        .sessions()
        .iter()
        .position(|existing| existing.session.name == imported_session.session.name);
    match existing_index {
        Some(index) => {
            let existing = &config.sessions()[index];
            if existing.session == imported_session.session {
                result.already_present += 1;
            } else {
                result.skipped_conflicting += 1;
            }
        }
        None => {
            result.imported += 1;
            config.add_session(imported_session);
        }
    }
}

fn normalize_putty_session(
    raw_session: RawPuttySession,
) -> Result<StoredSession, SessionImportSkip> {
    let protocol = parse_putty_protocol(&raw_session)?;
    let mut session = SessionConfig::new(raw_session.name.clone(), protocol);
    session.host_key_policy = HostKeyPolicy::Ask;
    session.saved_in = StorageFormat::PuttyImportOnly;

    match protocol {
        Protocol::Serial => {
            let serial_line = raw_session
                .non_empty_string("SerialLine")
                .ok_or(SessionImportSkip::Unlaunchable)?;
            session.host = Some(serial_line.to_owned());
        }
        _ => {
            let host = raw_session
                .non_empty_string("HostName")
                .ok_or(SessionImportSkip::Unlaunchable)?;
            session.host = Some(host.to_owned());

            if let Some(port) = parse_putty_port(&raw_session)? {
                session.port = Some(port);
            } else if protocol.default_port().is_none() {
                return Err(SessionImportSkip::Unlaunchable);
            }
        }
    }

    if let Some(username) = raw_session.non_empty_string("UserName") {
        session.username = Some(username.to_owned());
    }

    if let Some(private_key_path) = raw_session.non_empty_string("PublicKeyFile") {
        session.private_key_path = Some(private_key_path.to_owned());
    }

    let mut omitted_settings = BTreeSet::new();
    if protocol == Protocol::Ssh {
        import_putty_port_forwards(&raw_session, &mut session, &mut omitted_settings);
    } else if raw_session.non_empty_string("PortForwardings").is_some() {
        omitted_settings.insert("PortForwardings".to_owned());
    }

    collect_putty_omitted_settings(&raw_session, protocol, &mut omitted_settings);

    let mut stored_session = StoredSession::imported(session, raw_session.imported_from);
    if !omitted_settings.is_empty() {
        stored_session.notes = Some(format!(
            "PuTTY import did not translate: {}",
            omitted_settings.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    Ok(stored_session)
}

fn parse_putty_protocol(raw_session: &RawPuttySession) -> Result<Protocol, SessionImportSkip> {
    let Some(protocol_id) = raw_session.non_empty_string("Protocol") else {
        return Err(SessionImportSkip::Unlaunchable);
    };

    match protocol_id {
        "ssh" => Ok(Protocol::Ssh),
        "telnet" => Ok(Protocol::Telnet),
        "raw" => Ok(Protocol::Raw),
        "rlogin" => Ok(Protocol::Rlogin),
        "serial" => Ok(Protocol::Serial),
        "default" => Err(SessionImportSkip::Unlaunchable),
        _ => Err(SessionImportSkip::UnsupportedProtocol),
    }
}

fn parse_putty_port(raw_session: &RawPuttySession) -> Result<Option<u16>, SessionImportSkip> {
    let Some(port) = raw_session.int("PortNumber") else {
        return Ok(None);
    };
    let port = u16::try_from(port).map_err(|_| SessionImportSkip::Malformed)?;
    Ok(Some(port))
}

fn import_putty_port_forwards(
    raw_session: &RawPuttySession,
    session: &mut SessionConfig,
    omitted_settings: &mut BTreeSet<String>,
) {
    let Some(raw_value) = raw_session.non_empty_string("PortForwardings") else {
        return;
    };

    let mappings = parse_putty_mapping(raw_value);
    let mut had_invalid_forward = false;
    for (source, target) in mappings {
        let Some((kind, listen)) = source.split_at_checked(1) else {
            had_invalid_forward = true;
            continue;
        };

        match kind {
            "L" => {
                if target == "D" {
                    if listen.is_empty() {
                        had_invalid_forward = true;
                    } else {
                        session.add_dynamic_forward(listen);
                    }
                } else if listen.is_empty() || target.is_empty() {
                    had_invalid_forward = true;
                } else {
                    session.add_port_forward(listen, target);
                }
            }
            "R" => {
                if listen.is_empty() || target.is_empty() {
                    had_invalid_forward = true;
                } else {
                    session.add_remote_forward(listen, target);
                }
            }
            "D" => {
                if listen.is_empty() {
                    had_invalid_forward = true;
                } else {
                    session.add_dynamic_forward(listen);
                }
            }
            _ => had_invalid_forward = true,
        }
    }

    if had_invalid_forward {
        omitted_settings.insert("PortForwardings entries".to_owned());
    }
}

fn collect_putty_omitted_settings(
    raw_session: &RawPuttySession,
    protocol: Protocol,
    omitted_settings: &mut BTreeSet<String>,
) {
    if raw_session.bool("UserNameFromEnvironment") == Some(true) {
        omitted_settings.insert("UserNameFromEnvironment".to_owned());
    }

    if raw_session.bool("NoPTY") == Some(true) {
        omitted_settings.insert("NoPTY".to_owned());
    }

    if raw_session.bool("AgentFwd") == Some(true) {
        omitted_settings.insert("AgentFwd".to_owned());
    }

    if raw_session.bool("TryAgent") == Some(false) {
        omitted_settings.insert("TryAgent".to_owned());
    }

    if raw_session.non_empty_string("RemoteCommand").is_some() {
        omitted_settings.insert("RemoteCommand".to_owned());
    }

    if raw_session
        .int("ProxyMethod")
        .is_some_and(|value| value != 0)
    {
        omitted_settings.insert("Proxy settings".to_owned());
    }

    if raw_session
        .int("AddressFamily")
        .is_some_and(|value| value != 0)
    {
        omitted_settings.insert("AddressFamily".to_owned());
    }

    if raw_session.non_empty_string("SSHManualHostKeys").is_some() {
        omitted_settings.insert("SSHManualHostKeys".to_owned());
    }

    if protocol == Protocol::Serial
        && raw_session
            .int("SerialSpeed")
            .is_some_and(|value| value != 9600)
    {
        omitted_settings.insert("SerialSpeed".to_owned());
    }
}

fn parse_putty_mapping(raw_value: &str) -> Vec<(String, String)> {
    let mut mappings = Vec::new();
    let mut index = 0;
    let bytes = raw_value.as_bytes();

    while index < bytes.len() {
        let mut entry = String::new();
        let mut value_start = None;

        while index < bytes.len() && bytes[index] != b',' {
            let character = bytes[index] as char;
            index += 1;
            let actual = if character == '\\' && index < bytes.len() {
                let escaped = bytes[index] as char;
                index += 1;
                escaped
            } else {
                character
            };

            if actual == '=' && value_start.is_none() {
                value_start = Some(entry.len());
                entry.push('\0');
            } else {
                entry.push(actual);
            }
        }

        if index < bytes.len() && bytes[index] == b',' {
            index += 1;
        }

        let split_at = value_start.unwrap_or(entry.len());
        let key = entry[..split_at].to_owned();
        let value = if split_at < entry.len() {
            entry[split_at + 1..].to_owned()
        } else {
            String::new()
        };

        if !key.is_empty() {
            mappings.push((key, value));
        }
    }

    mappings
}

fn looks_like_registry_export(input: &str) -> bool {
    input
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with('[') && line.ends_with(']'))
}

fn parse_putty_registry_session_section(line: &str) -> Option<String> {
    let escaped_name = line
        .strip_prefix(PUTTY_SESSION_SECTION_PREFIX)?
        .strip_suffix(']')?;
    decode_putty_percent_escapes(escaped_name).ok()
}

fn parse_putty_registry_setting(line: &str) -> Option<(String, PuttySettingValue)> {
    let (key, remainder) = parse_registry_quoted_string(line)?;
    let remainder = remainder.trim_start();
    let remainder = remainder.strip_prefix('=')?.trim_start();

    if remainder.starts_with('"') {
        let (value, trailing) = parse_registry_quoted_string(remainder)?;
        if !trailing.trim().is_empty() {
            return None;
        }
        return Some((key, PuttySettingValue::String(value)));
    }

    let raw_dword = remainder
        .strip_prefix("dword:")
        .or_else(|| remainder.strip_prefix("DWORD:"))?;
    let raw_dword = raw_dword.trim();
    if raw_dword.is_empty() {
        return None;
    }

    let value = u32::from_str_radix(raw_dword, 16).ok()?;
    Some((key, PuttySettingValue::Dword(value)))
}

fn parse_registry_quoted_string(input: &str) -> Option<(String, &str)> {
    let remainder = input.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;

    for (index, character) in remainder.char_indices() {
        if escaped {
            output.push(character);
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '"' => {
                let trailing = &remainder[index + character.len_utf8()..];
                return Some((output, trailing));
            }
            _ => output.push(character),
        }
    }

    None
}

fn decode_putty_percent_escapes(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(());
            }
            let high = (bytes[index + 1] as char).to_digit(16).ok_or(())?;
            let low = (bytes[index + 2] as char).to_digit(16).ok_or(())?;
            decoded.push(((high << 4) | low) as u8);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| ())
}

fn is_blank_or_comment_line(line: &str) -> bool {
    line.is_empty() || line.starts_with(';') || line.starts_with('#')
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rustty_core::Protocol;

    use super::{import_putty_sessions, parse_putty_mapping};
    use crate::{ImportSource, load_config, save_config};

    #[test]
    fn parse_putty_mapping_understands_port_forward_storage() {
        let mappings =
            parse_putty_mapping(r"L127.0.0.1\:15432=127.0.0.1\:5432,D1080,R18080=127.0.0.1\:8080");
        assert_eq!(
            mappings,
            vec![
                ("L127.0.0.1:15432".to_owned(), "127.0.0.1:5432".to_owned()),
                ("D1080".to_owned(), String::new()),
                ("R18080".to_owned(), "127.0.0.1:8080".to_owned()),
            ]
        );
    }

    #[test]
    fn import_putty_session_directory_merges_supported_sessions() {
        let workspace = temporary_workspace();
        let source_dir = workspace.join("sessions");
        let config_path = workspace.join("config.toml");
        std::fs::create_dir_all(&source_dir).expect("sessions directory should exist");

        std::fs::write(
            source_dir.join("Prod%20SSH"),
            "\
HostName=prod.example.com
Protocol=ssh
PortNumber=2222
UserName=ops
PublicKeyFile=/keys/prod.ppk
PortForwardings=L127.0.0.1\\:15432=127.0.0.1\\:5432,D1080,R18080=127.0.0.1\\:8080
ProxyMethod=3
RemoteCommand=uptime
",
        )
        .expect("SSH session should be written");
        std::fs::write(
            source_dir.join("Serial%20Lab"),
            "\
Protocol=serial
SerialLine=/dev/ttyUSB0
SerialSpeed=115200
",
        )
        .expect("serial session should be written");

        let result =
            import_putty_sessions(&source_dir, &config_path, false).expect("import should work");

        assert_eq!(result.discovered_sessions, 2);
        assert_eq!(result.imported, 2);
        assert_eq!(result.already_present, 0);
        assert_eq!(result.skipped_blank_or_comment, 0);
        assert_eq!(result.skipped_outside_target, 0);
        assert_eq!(result.skipped_malformed, 0);
        assert_eq!(result.skipped_unsupported_protocol, 0);
        assert_eq!(result.skipped_unlaunchable, 0);
        assert_eq!(result.skipped_conflicting, 0);

        let config = load_config(&config_path).expect("imported config should load");
        assert_eq!(config.session_count(), 2);

        let prod = config
            .find_session("Prod SSH")
            .expect("SSH session should be imported");
        assert_eq!(prod.imported_from, Some(ImportSource::PuttySessionFile));
        assert_eq!(prod.session.protocol, Protocol::Ssh);
        assert_eq!(prod.session.host.as_deref(), Some("prod.example.com"));
        assert_eq!(prod.session.port, Some(2222));
        assert_eq!(prod.session.username.as_deref(), Some("ops"));
        assert_eq!(
            prod.session.private_key_path.as_deref(),
            Some("/keys/prod.ppk")
        );
        assert_eq!(prod.session.port_forwards.len(), 1);
        assert_eq!(prod.session.dynamic_forwards.len(), 1);
        assert_eq!(prod.session.remote_forwards.len(), 1);
        assert_eq!(
            prod.notes.as_deref(),
            Some("PuTTY import did not translate: Proxy settings, RemoteCommand")
        );

        let serial = config
            .find_session("Serial Lab")
            .expect("serial session should be imported");
        assert_eq!(serial.session.protocol, Protocol::Serial);
        assert_eq!(serial.session.host.as_deref(), Some("/dev/ttyUSB0"));
        assert_eq!(
            serial.notes.as_deref(),
            Some("PuTTY import did not translate: SerialSpeed")
        );
    }

    #[test]
    fn import_putty_registry_export_supports_utf16_dword_and_skip_counts() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("putty-sessions.reg");
        let config_path = workspace.join("config.toml");
        let registry_export = "\
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Jumplist]
\"Recent sessions\"=\"prod\"

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\Prod%20SSH]
\"HostName\"=\"prod.example.com\"
\"Protocol\"=\"ssh\"
\"PortNumber\"=dword:000008ae
\"UserName\"=\"ops\"

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\Old%20SUPDUP]
\"HostName\"=\"legacy.example.com\"
\"Protocol\"=\"supdup\"
";
        std::fs::write(&source_path, encode_utf16le_with_bom(registry_export))
            .expect("registry export should be written");

        let result =
            import_putty_sessions(&source_path, &config_path, true).expect("import should work");

        assert_eq!(result.discovered_sessions, 2);
        assert_eq!(result.imported, 1);
        assert_eq!(result.skipped_blank_or_comment, 3);
        assert_eq!(result.skipped_outside_target, 3);
        assert_eq!(result.skipped_unsupported_protocol, 1);
        assert_eq!(result.skipped_malformed, 0);
        assert!(!config_path.exists());
    }

    #[test]
    fn import_putty_sessions_skips_conflicting_existing_session_names() {
        let workspace = temporary_workspace();
        let source_dir = workspace.join("sessions");
        let config_path = workspace.join("config.toml");
        std::fs::create_dir_all(&source_dir).expect("sessions directory should exist");
        std::fs::write(
            source_dir.join("Prod%20SSH"),
            "HostName=prod.example.com\nProtocol=ssh\n",
        )
        .expect("source session should be written");

        let mut existing = crate::AppConfig::empty();
        existing.add_session(crate::StoredSession::new(
            rustty_core::SessionConfig::new("Prod SSH", Protocol::Ssh).with_host("other.example"),
        ));
        save_config(&config_path, &existing).expect("existing config should save");

        let result =
            import_putty_sessions(&source_dir, &config_path, false).expect("import should work");

        assert_eq!(result.imported, 0);
        assert_eq!(result.skipped_conflicting, 1);
        let loaded = load_config(&config_path).expect("existing config should still load");
        assert_eq!(
            loaded
                .find_session("Prod SSH")
                .expect("existing session should remain")
                .session
                .host
                .as_deref(),
            Some("other.example")
        );
    }

    #[test]
    fn import_putty_sessions_counts_identical_existing_sessions_as_already_present() {
        let workspace = temporary_workspace();
        let source_dir = workspace.join("sessions");
        let config_path = workspace.join("config.toml");
        std::fs::create_dir_all(&source_dir).expect("sessions directory should exist");
        std::fs::write(
            source_dir.join("Prod%20SSH"),
            "HostName=prod.example.com\nProtocol=ssh\nUserName=ops\n",
        )
        .expect("source session should be written");

        let mut existing = crate::AppConfig::empty();
        let mut session = rustty_core::SessionConfig::new("Prod SSH", Protocol::Ssh);
        session.host = Some("prod.example.com".to_owned());
        session.username = Some("ops".to_owned());
        session.saved_in = rustty_core::StorageFormat::PuttyImportOnly;
        existing.add_session(crate::StoredSession::imported(
            session,
            ImportSource::PuttySessionFile,
        ));
        save_config(&config_path, &existing).expect("existing config should save");

        let result =
            import_putty_sessions(&source_dir, &config_path, false).expect("import should work");

        assert_eq!(result.imported, 0);
        assert_eq!(result.already_present, 1);
    }

    fn encode_utf16le_with_bom(input: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in input.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustty-putty-session-import-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
