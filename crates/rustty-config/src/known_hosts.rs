//! Known-hosts lookup, persistence, and migration helpers for RusTTY.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ssh_key::{
    Mpint, PublicKey,
    known_hosts::{Entry, HostPatterns},
    public::{DsaPublicKey, EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
};

use crate::{ConfigError, text::read_text_with_bom};

/// A stored host key that matched an exact RusTTY host and port lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownHostKey {
    /// 1-based line number in the known-hosts file.
    pub line_number: usize,
    /// Host pattern that matched the requested host and port.
    pub pattern: String,
    /// Trusted public key from the known-hosts file.
    pub public_key: PublicKey,
}

/// Result of appending a RusTTY-managed known-host entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistKnownHostResult {
    /// Known-hosts path that was requested.
    pub path: PathBuf,
    /// Whether the file contents changed.
    pub changed: bool,
}

/// Summary of importing host keys from an OpenSSH-style known-hosts file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportKnownHostsResult {
    /// Imported source file path.
    pub source_path: PathBuf,
    /// RusTTY known-hosts path that received imported entries.
    pub destination_path: PathBuf,
    /// Exact host patterns that were newly imported.
    pub imported: usize,
    /// Exact host patterns that were already trusted.
    pub already_present: usize,
    /// Blank or comment lines skipped before parsing.
    pub skipped_blank_or_comment: usize,
    /// Lines skipped because they use known-host markers.
    pub skipped_marked: usize,
    /// Host patterns skipped because they use hashed hostnames.
    pub skipped_hashed: usize,
    /// Host patterns skipped because they use wildcard matching.
    pub skipped_wildcard: usize,
    /// Host patterns skipped because they use negation.
    pub skipped_negated: usize,
    /// Host patterns skipped because RusTTY cannot normalize them yet.
    pub skipped_unsupported: usize,
}

impl ImportKnownHostsResult {
    /// Total number of skipped lines or patterns in the import report.
    pub fn skipped_total(&self) -> usize {
        self.skipped_blank_or_comment
            + self.skipped_marked
            + self.skipped_hashed
            + self.skipped_wildcard
            + self.skipped_negated
            + self.skipped_unsupported
    }
}

/// Summary of importing host keys from a PuTTY registry export or `sshhostkeys`
/// file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPuttyHostKeysResult {
    /// Imported source file path.
    pub source_path: PathBuf,
    /// RusTTY known-hosts path that received imported entries.
    pub destination_path: PathBuf,
    /// Entries that were newly imported.
    pub imported: usize,
    /// Entries that were already trusted.
    pub already_present: usize,
    /// Blank or comment lines skipped before parsing.
    pub skipped_blank_or_comment: usize,
    /// Registry-export lines outside the PuTTY host-key section.
    pub skipped_outside_target: usize,
    /// Entries skipped because their format could not be parsed.
    pub skipped_malformed: usize,
    /// Entries skipped because their key type is not supported yet.
    pub skipped_unsupported_key_type: usize,
}

impl ImportPuttyHostKeysResult {
    /// Total number of skipped lines or records in the import report.
    pub fn skipped_total(&self) -> usize {
        self.skipped_blank_or_comment
            + self.skipped_outside_target
            + self.skipped_malformed
            + self.skipped_unsupported_key_type
    }
}

/// Loads all exact known-host keys for a host and port pair.
pub fn load_known_host_keys(
    path: impl AsRef<Path>,
    host: &str,
    port: u16,
) -> Result<Vec<KnownHostKey>, ConfigError> {
    let path = path.as_ref().to_path_buf();
    let input = match fs::read_to_string(&path) {
        Ok(input) => input,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.clone(),
                source,
            });
        }
    };

    let mut matches = Vec::new();
    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let Some(parsed) = parse_known_host_line(&path, line_number, raw_line)? else {
            continue;
        };

        if parsed.marker().is_some() {
            continue;
        }

        let HostPatterns::Patterns(patterns) = parsed.host_patterns() else {
            continue;
        };

        for pattern in patterns {
            if is_exact_host_pattern_match(pattern, host, port) {
                matches.push(KnownHostKey {
                    line_number,
                    pattern: pattern.clone(),
                    public_key: parsed.public_key().clone(),
                });
            }
        }
    }

    Ok(matches)
}

/// Appends a RusTTY-managed host key when it is not already trusted.
pub fn persist_known_host_key(
    path: impl AsRef<Path>,
    host: &str,
    port: u16,
    public_key: &PublicKey,
) -> Result<PersistKnownHostResult, ConfigError> {
    let path = path.as_ref().to_path_buf();
    let existing_keys = load_known_host_keys(&path, host, port)?;
    if existing_keys
        .iter()
        .any(|known_host| known_host.public_key == *public_key)
    {
        return Ok(PersistKnownHostResult {
            path,
            changed: false,
        });
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let needs_newline = path.exists()
        && fs::metadata(&path)
            .map_err(|source| ConfigError::Io {
                path: path.clone(),
                source,
            })?
            .len()
            > 0
        && !fs::read_to_string(&path)
            .map_err(|source| ConfigError::Io {
                path: path.clone(),
                source,
            })?
            .ends_with('\n');

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;

    if needs_newline {
        file.write_all(b"\n").map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
    }

    let rendered_key = public_key.to_string();
    writeln!(file, "{} {}", render_host_pattern(host, port), rendered_key).map_err(|source| {
        ConfigError::Io {
            path: path.clone(),
            source,
        }
    })?;

    Ok(PersistKnownHostResult {
        path,
        changed: true,
    })
}

/// Imports exact OpenSSH-style host keys into a RusTTY-managed known-hosts file.
pub fn import_known_hosts(
    source_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    dry_run: bool,
) -> Result<ImportKnownHostsResult, ConfigError> {
    let source_path = source_path.as_ref().to_path_buf();
    let destination_path = destination_path.as_ref().to_path_buf();
    let input = fs::read_to_string(&source_path).map_err(|source| ConfigError::Io {
        path: source_path.clone(),
        source,
    })?;

    let mut result = ImportKnownHostsResult {
        source_path: source_path.clone(),
        destination_path: destination_path.clone(),
        imported: 0,
        already_present: 0,
        skipped_blank_or_comment: 0,
        skipped_marked: 0,
        skipped_hashed: 0,
        skipped_wildcard: 0,
        skipped_negated: 0,
        skipped_unsupported: 0,
    };

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        if is_blank_or_comment_line(raw_line) {
            result.skipped_blank_or_comment += 1;
            continue;
        }

        let Some(parsed) = parse_known_host_line(&source_path, line_number, raw_line)? else {
            result.skipped_blank_or_comment += 1;
            continue;
        };

        if parsed.marker().is_some() {
            result.skipped_marked += 1;
            continue;
        }

        let HostPatterns::Patterns(patterns) = parsed.host_patterns() else {
            result.skipped_hashed += 1;
            continue;
        };

        for pattern in patterns {
            match classify_import_pattern(pattern) {
                ImportPattern::Exact { host, port } => {
                    let changed = would_persist_known_host_key(
                        &destination_path,
                        &host,
                        port,
                        parsed.public_key(),
                    )?;
                    if !dry_run && changed {
                        persist_known_host_key(
                            &destination_path,
                            &host,
                            port,
                            parsed.public_key(),
                        )?;
                    }

                    if changed {
                        result.imported += 1;
                    } else {
                        result.already_present += 1;
                    }
                }
                ImportPattern::Hashed => result.skipped_hashed += 1,
                ImportPattern::Wildcard => result.skipped_wildcard += 1,
                ImportPattern::Negated => result.skipped_negated += 1,
                ImportPattern::Unsupported => result.skipped_unsupported += 1,
            }
        }
    }

    Ok(result)
}

/// Imports PuTTY host keys into a RusTTY-managed known-hosts file.
pub fn import_putty_host_keys(
    source_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    dry_run: bool,
) -> Result<ImportPuttyHostKeysResult, ConfigError> {
    let source_path = source_path.as_ref().to_path_buf();
    let destination_path = destination_path.as_ref().to_path_buf();
    let input = read_text_with_bom(&source_path)?;

    let mut result = ImportPuttyHostKeysResult {
        source_path: source_path.clone(),
        destination_path: destination_path.clone(),
        imported: 0,
        already_present: 0,
        skipped_blank_or_comment: 0,
        skipped_outside_target: 0,
        skipped_malformed: 0,
        skipped_unsupported_key_type: 0,
    };

    if looks_like_putty_registry_export(&input) {
        import_putty_registry_export(
            &source_path,
            &destination_path,
            &input,
            dry_run,
            &mut result,
        )?;
    } else {
        import_putty_unix_hostkeys(
            &source_path,
            &destination_path,
            &input,
            dry_run,
            &mut result,
        )?;
    }

    Ok(result)
}

fn parse_known_host_line(
    path: &Path,
    line_number: usize,
    raw_line: &str,
) -> Result<Option<Entry>, ConfigError> {
    let trimmed = raw_line.trim_end();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    trimmed
        .parse::<Entry>()
        .map(Some)
        .map_err(|source| ConfigError::KnownHostsParse {
            path: path.to_path_buf(),
            line: line_number,
            source,
        })
}

fn is_blank_or_comment_line(raw_line: &str) -> bool {
    let trimmed = raw_line.trim_end();
    trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';')
}

fn would_persist_known_host_key(
    path: &Path,
    host: &str,
    port: u16,
    public_key: &PublicKey,
) -> Result<bool, ConfigError> {
    let existing_keys = load_known_host_keys(path, host, port)?;
    Ok(existing_keys
        .iter()
        .all(|known_host| known_host.public_key != *public_key))
}

fn is_exact_host_pattern_match(pattern: &str, host: &str, port: u16) -> bool {
    if pattern.starts_with('!') || pattern.contains('*') || pattern.contains('?') {
        return false;
    }

    pattern == render_host_pattern(host, port)
        || (port == 22 && (pattern == host || pattern == format!("[{host}]:22")))
}

fn render_host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

const PUTTY_REGISTRY_SECTION: &str =
    "[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\SshHostKeys]";

fn looks_like_putty_registry_export(input: &str) -> bool {
    input
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with('[') && line.ends_with(']'))
}

fn import_putty_registry_export(
    source_path: &Path,
    destination_path: &Path,
    input: &str,
    dry_run: bool,
    result: &mut ImportPuttyHostKeysResult,
) -> Result<(), ConfigError> {
    let mut in_target_section = false;

    for raw_line in input.lines() {
        let trimmed = raw_line.trim();
        if is_blank_or_comment_line(trimmed) {
            result.skipped_blank_or_comment += 1;
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_target_section = trimmed.eq_ignore_ascii_case(PUTTY_REGISTRY_SECTION);
            if !in_target_section {
                result.skipped_outside_target += 1;
            }
            continue;
        }

        if !in_target_section {
            result.skipped_outside_target += 1;
            continue;
        }

        let Some((key_name, raw_value)) = parse_putty_registry_entry(trimmed) else {
            result.skipped_malformed += 1;
            continue;
        };

        apply_putty_host_key_record(
            source_path,
            destination_path,
            PuttyRecord {
                key_name: key_name.to_owned(),
                raw_value: raw_value.to_owned(),
                host_is_escaped: true,
            },
            dry_run,
            result,
        )?;
    }

    Ok(())
}

fn import_putty_unix_hostkeys(
    source_path: &Path,
    destination_path: &Path,
    input: &str,
    dry_run: bool,
    result: &mut ImportPuttyHostKeysResult,
) -> Result<(), ConfigError> {
    for raw_line in input.lines() {
        let trimmed = raw_line.trim();
        if is_blank_or_comment_line(trimmed) {
            result.skipped_blank_or_comment += 1;
            continue;
        }

        let Some((key_name, raw_value)) = parse_putty_unix_entry(trimmed) else {
            result.skipped_malformed += 1;
            continue;
        };

        apply_putty_host_key_record(
            source_path,
            destination_path,
            PuttyRecord {
                key_name: key_name.to_owned(),
                raw_value: raw_value.to_owned(),
                host_is_escaped: false,
            },
            dry_run,
            result,
        )?;
    }

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PuttyRecord {
    key_name: String,
    raw_value: String,
    host_is_escaped: bool,
}

fn apply_putty_host_key_record(
    source_path: &Path,
    destination_path: &Path,
    record: PuttyRecord,
    dry_run: bool,
    result: &mut ImportPuttyHostKeysResult,
) -> Result<(), ConfigError> {
    let parsed_name = match parse_putty_key_name(&record.key_name, record.host_is_escaped) {
        Ok(parsed_name) => parsed_name,
        Err(PuttyRecordError::Malformed) => {
            result.skipped_malformed += 1;
            return Ok(());
        }
        Err(PuttyRecordError::UnsupportedKeyType) => {
            result.skipped_unsupported_key_type += 1;
            return Ok(());
        }
    };

    let public_key = match parse_putty_public_key(
        source_path,
        &record.key_name,
        &record.raw_value,
        parsed_name.key_type,
    ) {
        Ok(public_key) => public_key,
        Err(PuttyRecordError::Malformed) => {
            result.skipped_malformed += 1;
            return Ok(());
        }
        Err(PuttyRecordError::UnsupportedKeyType) => {
            result.skipped_unsupported_key_type += 1;
            return Ok(());
        }
    };

    let changed = would_persist_known_host_key(
        destination_path,
        &parsed_name.host,
        parsed_name.port,
        &public_key,
    )?;
    if !dry_run && changed {
        persist_known_host_key(
            destination_path,
            &parsed_name.host,
            parsed_name.port,
            &public_key,
        )?;
    }

    if changed {
        result.imported += 1;
    } else {
        result.already_present += 1;
    }

    Ok(())
}

fn parse_putty_registry_entry(line: &str) -> Option<(&str, &str)> {
    let (key_name, remainder) = parse_quoted_field(line)?;
    let remainder = remainder.trim_start();
    let remainder = remainder.strip_prefix('=')?.trim_start();
    let (raw_value, trailing) = parse_quoted_field(remainder)?;
    if !trailing.trim().is_empty() {
        return None;
    }
    Some((key_name, raw_value))
}

fn parse_putty_unix_entry(line: &str) -> Option<(&str, &str)> {
    let separator_index = line.find(char::is_whitespace)?;
    let (key_name, remainder) = line.split_at(separator_index);
    let raw_value = remainder.trim();
    if key_name.is_empty() || raw_value.is_empty() {
        return None;
    }
    Some((key_name, raw_value))
}

fn parse_quoted_field(input: &str) -> Option<(&str, &str)> {
    let input = input.strip_prefix('"')?;
    let end_index = input.find('"')?;
    Some((&input[..end_index], &input[end_index + 1..]))
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PuttyKeyType {
    Rsa,
    Dsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PuttyRecordError {
    Malformed,
    UnsupportedKeyType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedPuttyKeyName {
    key_type: PuttyKeyType,
    host: String,
    port: u16,
}

fn parse_putty_key_name(
    raw_key_name: &str,
    host_is_escaped: bool,
) -> Result<ParsedPuttyKeyName, PuttyRecordError> {
    let (raw_key_type, remainder) = raw_key_name
        .split_once('@')
        .ok_or(PuttyRecordError::Malformed)?;
    let (raw_port, raw_host) = remainder
        .split_once(':')
        .ok_or(PuttyRecordError::Malformed)?;
    let key_type = match raw_key_type {
        "rsa2" => PuttyKeyType::Rsa,
        "dss" => PuttyKeyType::Dsa,
        "ecdsa-sha2-nistp256" => PuttyKeyType::EcdsaP256,
        "ecdsa-sha2-nistp384" => PuttyKeyType::EcdsaP384,
        "ecdsa-sha2-nistp521" => PuttyKeyType::EcdsaP521,
        "ssh-ed25519" => PuttyKeyType::Ed25519,
        "rsa" | "ssh-ed448" => return Err(PuttyRecordError::UnsupportedKeyType),
        _ => return Err(PuttyRecordError::UnsupportedKeyType),
    };

    let port = raw_port
        .parse::<u16>()
        .map_err(|_| PuttyRecordError::Malformed)?;
    if raw_host.is_empty() {
        return Err(PuttyRecordError::Malformed);
    }

    let host = if host_is_escaped {
        unescape_putty_registry_host(raw_host)?
    } else {
        raw_host.to_owned()
    };

    Ok(ParsedPuttyKeyName {
        key_type,
        host,
        port,
    })
}

fn parse_putty_public_key(
    _source_path: &Path,
    _key_name: &str,
    raw_value: &str,
    key_type: PuttyKeyType,
) -> Result<PublicKey, PuttyRecordError> {
    match key_type {
        PuttyKeyType::Rsa => parse_putty_rsa_public_key(raw_value),
        PuttyKeyType::Dsa => parse_putty_dsa_public_key(raw_value),
        PuttyKeyType::EcdsaP256 => parse_putty_ecdsa_public_key(raw_value, "nistp256", 32),
        PuttyKeyType::EcdsaP384 => parse_putty_ecdsa_public_key(raw_value, "nistp384", 48),
        PuttyKeyType::EcdsaP521 => parse_putty_ecdsa_public_key(raw_value, "nistp521", 66),
        PuttyKeyType::Ed25519 => parse_putty_ed25519_public_key(raw_value),
    }
}

fn parse_putty_rsa_public_key(raw_value: &str) -> Result<PublicKey, PuttyRecordError> {
    let components = split_putty_value_components(raw_value);
    if components.len() != 2 {
        return Err(PuttyRecordError::Malformed);
    }

    let public_key = RsaPublicKey {
        e: parse_putty_mpint(components[0])?,
        n: parse_putty_mpint(components[1])?,
    };
    Ok(PublicKey::new(KeyData::from(public_key), ""))
}

fn parse_putty_dsa_public_key(raw_value: &str) -> Result<PublicKey, PuttyRecordError> {
    let components = split_putty_value_components(raw_value);
    if components.len() != 4 {
        return Err(PuttyRecordError::Malformed);
    }

    let public_key = DsaPublicKey {
        p: parse_putty_mpint(components[0])?,
        q: parse_putty_mpint(components[1])?,
        g: parse_putty_mpint(components[2])?,
        y: parse_putty_mpint(components[3])?,
    };
    Ok(PublicKey::new(KeyData::from(public_key), ""))
}

fn parse_putty_ecdsa_public_key(
    raw_value: &str,
    expected_curve: &str,
    coordinate_size: usize,
) -> Result<PublicKey, PuttyRecordError> {
    let components = split_putty_value_components(raw_value);
    if components.len() != 3 || components[0] != expected_curve {
        return Err(PuttyRecordError::Malformed);
    }

    let x = parse_fixed_width_hex_bytes(components[1], coordinate_size)?;
    let y = parse_fixed_width_hex_bytes(components[2], coordinate_size)?;
    let mut encoded_point = Vec::with_capacity(1 + x.len() + y.len());
    encoded_point.push(0x04);
    encoded_point.extend_from_slice(&x);
    encoded_point.extend_from_slice(&y);

    let public_key =
        EcdsaPublicKey::from_sec1_bytes(&encoded_point).map_err(|_| PuttyRecordError::Malformed)?;
    Ok(PublicKey::new(KeyData::from(public_key), ""))
}

fn parse_putty_ed25519_public_key(raw_value: &str) -> Result<PublicKey, PuttyRecordError> {
    let components = split_putty_value_components(raw_value);
    if components.len() != 2 {
        return Err(PuttyRecordError::Malformed);
    }

    let x = parse_hex_big_endian_bytes(components[0])?;
    let y = parse_fixed_width_hex_bytes(components[1], Ed25519PublicKey::BYTE_SIZE)?;
    let x_parity = x.last().copied().unwrap_or_default() & 1;

    let mut compressed_point = [0u8; Ed25519PublicKey::BYTE_SIZE];
    if y.first().copied().unwrap_or_default() & 0x80 != 0 {
        return Err(PuttyRecordError::Malformed);
    }

    for (index, byte) in y.iter().rev().enumerate() {
        compressed_point[index] = *byte;
    }
    compressed_point[Ed25519PublicKey::BYTE_SIZE - 1] |= x_parity << 7;

    let public_key = Ed25519PublicKey::try_from(&compressed_point[..])
        .map_err(|_| PuttyRecordError::Malformed)?;
    Ok(PublicKey::new(KeyData::from(public_key), ""))
}

fn split_putty_value_components(raw_value: &str) -> Vec<&str> {
    raw_value
        .split(',')
        .map(str::trim)
        .filter(|component| !component.is_empty())
        .collect()
}

fn parse_putty_mpint(raw_value: &str) -> Result<Mpint, PuttyRecordError> {
    let bytes = parse_hex_big_endian_bytes(raw_value)?;
    Mpint::from_positive_bytes(&bytes).map_err(|_| PuttyRecordError::Malformed)
}

fn parse_fixed_width_hex_bytes(
    raw_value: &str,
    expected_length: usize,
) -> Result<Vec<u8>, PuttyRecordError> {
    let bytes = parse_hex_big_endian_bytes(raw_value)?;
    if bytes.len() > expected_length {
        return Err(PuttyRecordError::Malformed);
    }

    let mut padded = vec![0u8; expected_length - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

fn parse_hex_big_endian_bytes(raw_value: &str) -> Result<Vec<u8>, PuttyRecordError> {
    let digits = raw_value
        .strip_prefix("0x")
        .or_else(|| raw_value.strip_prefix("0X"))
        .ok_or(PuttyRecordError::Malformed)?;
    if digits.is_empty() {
        return Err(PuttyRecordError::Malformed);
    }

    let mut bytes = Vec::with_capacity(digits.len().div_ceil(2));
    let mut chars = digits.chars();
    if digits.len() % 2 != 0 {
        let low = chars.next().ok_or(PuttyRecordError::Malformed)?;
        bytes.push(parse_hex_nibble(low)?);
    }

    while let Some(high) = chars.next() {
        let low = chars.next().ok_or(PuttyRecordError::Malformed)?;
        bytes.push((parse_hex_nibble(high)? << 4) | parse_hex_nibble(low)?);
    }

    while bytes.first().copied() == Some(0) && bytes.len() > 1 {
        bytes.remove(0);
    }

    Ok(bytes)
}

fn parse_hex_nibble(character: char) -> Result<u8, PuttyRecordError> {
    character
        .to_digit(16)
        .map(|digit| digit as u8)
        .ok_or(PuttyRecordError::Malformed)
}

fn unescape_putty_registry_host(raw_host: &str) -> Result<String, PuttyRecordError> {
    let bytes = raw_host.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(PuttyRecordError::Malformed);
            }
            let high = (bytes[index + 1] as char)
                .to_digit(16)
                .ok_or(PuttyRecordError::Malformed)?;
            let low = (bytes[index + 2] as char)
                .to_digit(16)
                .ok_or(PuttyRecordError::Malformed)?;
            decoded.push(((high << 4) | low) as u8);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| PuttyRecordError::Malformed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ImportPattern {
    Exact { host: String, port: u16 },
    Hashed,
    Wildcard,
    Negated,
    Unsupported,
}

fn classify_import_pattern(pattern: &str) -> ImportPattern {
    if pattern.starts_with('|') {
        return ImportPattern::Hashed;
    }

    if pattern.starts_with('!') {
        return ImportPattern::Negated;
    }

    if pattern.contains('*') || pattern.contains('?') {
        return ImportPattern::Wildcard;
    }

    if let Some(bracketed) = pattern.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return ImportPattern::Unsupported;
        };
        let Some(raw_port) = suffix.strip_prefix(':') else {
            return ImportPattern::Unsupported;
        };
        if host.is_empty() {
            return ImportPattern::Unsupported;
        }
        let Ok(port) = raw_port.parse::<u16>() else {
            return ImportPattern::Unsupported;
        };
        return ImportPattern::Exact {
            host: host.to_owned(),
            port,
        };
    }

    if pattern.is_empty() {
        return ImportPattern::Unsupported;
    }

    ImportPattern::Exact {
        host: pattern.to_owned(),
        port: 22,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ssh_key::PublicKey;

    use super::{
        import_known_hosts, import_putty_host_keys, load_known_host_keys, persist_known_host_key,
    };

    #[test]
    fn load_missing_file_returns_no_matches() {
        let workspace = temporary_workspace();
        let path = workspace.join("known_hosts");
        let matches =
            load_known_host_keys(&path, "example.com", 22).expect("missing file should work");
        assert!(matches.is_empty());
    }

    #[test]
    fn persist_and_load_default_port_entry() {
        let workspace = temporary_workspace();
        let path = workspace.join("known_hosts");
        let public_key = sample_key();

        let write_result = persist_known_host_key(&path, "example.com", 22, &public_key)
            .expect("host key should be written");
        assert!(write_result.changed);

        let matches =
            load_known_host_keys(&path, "example.com", 22).expect("known host should load");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern, "example.com");
        assert_eq!(matches[0].public_key, public_key);
    }

    #[test]
    fn persist_and_load_non_default_port_entry() {
        let workspace = temporary_workspace();
        let path = workspace.join("known_hosts");
        let public_key = sample_key();

        persist_known_host_key(&path, "db.example.com", 2200, &public_key)
            .expect("host key should be written");
        let matches =
            load_known_host_keys(&path, "db.example.com", 2200).expect("known host should load");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern, "[db.example.com]:2200");
    }

    #[test]
    fn persist_is_idempotent_for_same_host_key() {
        let workspace = temporary_workspace();
        let path = workspace.join("known_hosts");
        let public_key = sample_key();

        let first = persist_known_host_key(&path, "example.com", 22, &public_key)
            .expect("first write should succeed");
        let second = persist_known_host_key(&path, "example.com", 22, &public_key)
            .expect("duplicate write should succeed");

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("known-hosts file should be readable"),
            format!("example.com {}\n", public_key.to_string())
        );
    }

    #[test]
    fn import_known_hosts_copies_exact_entries_and_reports_skips() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("source_known_hosts");
        let destination_path = workspace.join("destination_known_hosts");
        let public_key = sample_key().to_string();

        std::fs::write(
            &source_path,
            format!(
                "\
# imported test fixture
example.com {public_key}
example.com,alias.example.com {public_key}
[db.example.com]:2200 {public_key}
*.example.com {public_key}
!blocked.example.com {public_key}
@cert-authority example.com {public_key}
|1|AAAAAAAAAAAAAAAAAAAAAAAAAAA=|AAAAAAAAAAAAAAAAAAAAAAAAAAA= {public_key}
"
            ),
        )
        .expect("source known-hosts file should be written");

        let result =
            import_known_hosts(&source_path, &destination_path, false).expect("import should work");

        assert_eq!(result.imported, 3);
        assert_eq!(result.already_present, 1);
        assert_eq!(result.skipped_blank_or_comment, 1);
        assert_eq!(result.skipped_marked, 1);
        assert_eq!(result.skipped_hashed, 1);
        assert_eq!(result.skipped_wildcard, 1);
        assert_eq!(result.skipped_negated, 1);
        assert_eq!(result.skipped_unsupported, 0);

        let example_keys =
            load_known_host_keys(&destination_path, "example.com", 22).expect("key should load");
        assert_eq!(example_keys.len(), 1);
        let alias_keys = load_known_host_keys(&destination_path, "alias.example.com", 22)
            .expect("alias should load");
        assert_eq!(alias_keys.len(), 1);
        let db_keys = load_known_host_keys(&destination_path, "db.example.com", 2200)
            .expect("non-default port key should load");
        assert_eq!(db_keys.len(), 1);
    }

    #[test]
    fn import_known_hosts_dry_run_reports_without_writing_destination() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("source_known_hosts");
        let destination_path = workspace.join("destination_known_hosts");
        let public_key = sample_key().to_string();

        std::fs::write(&source_path, format!("example.com {public_key}\n"))
            .expect("source known-hosts file should be written");

        let result = import_known_hosts(&source_path, &destination_path, true)
            .expect("dry-run import should work");

        assert_eq!(result.imported, 1);
        assert!(!destination_path.exists());
    }

    #[test]
    fn import_putty_unix_hostkeys_imports_supported_records() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("sshhostkeys");
        let destination_path = workspace.join("known_hosts");

        std::fs::write(
            &source_path,
            "\
# PuTTY host keys
rsa2@22:rsa.example 0x10001,0xc782612a8d142031f6f4f7ba1f70c22df1a02e5e3266022e58230614f62b390004bc76034eedf140e16141a5189b9c102dc6e2cb733234c243fea9395d0cc1c7659b546fda89157340ba974d34e2fc17b619433fd3c68e69a93188b1496638dbdd38acf1c69c7113249eba0e27a0f5847487338a5d601748c78218fac7a606505a63003be9420b74f1bdf17a750cc37c7f733f929078583be0d0091cca5282de262021b460d3d7190391fe6e59074de8eda16304ae3cd2c88f916b09e00a9aad7594306bd3603269a42c66815a30f82388e75386670ac605ffc1229423b8c7f2e36473a0523a03e713246d88e38835169104004871751d1486201145d73cfe67
ssh-ed25519@22:example.com 0x322b390462b441b639beb9a19d6300e7ade71eae06a35e321b45e5cbff5162e8,0x62ab4ac5f52743d13ef4a429b5f1651f244ea3deef0d01aa7cdfa27ef3ae3eb3
ssh-ed448@22:skip.example 0x1,0x2
broken line
",
        )
        .expect("sshhostkeys source should be written");

        let result = import_putty_host_keys(&source_path, &destination_path, false)
            .expect("PuTTY host-key import should work");

        assert_eq!(result.imported, 2);
        assert_eq!(result.already_present, 0);
        assert_eq!(result.skipped_blank_or_comment, 1);
        assert_eq!(result.skipped_outside_target, 0);
        assert_eq!(result.skipped_malformed, 1);
        assert_eq!(result.skipped_unsupported_key_type, 1);

        assert_eq!(
            load_known_host_keys(&destination_path, "rsa.example", 22)
                .expect("RSA host should load")
                .len(),
            1
        );
        assert_eq!(
            load_known_host_keys(&destination_path, "example.com", 22)
                .expect("Ed25519 host should load")
                .len(),
            1
        );
    }

    #[test]
    fn import_putty_registry_export_supports_utf16_and_host_unescape() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("putty-hostkeys.reg");
        let destination_path = workspace.join("known_hosts");
        let registry_export = "\
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions]
\"Ignored\"=\"value\"

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\SshHostKeys]
\"ssh-ed25519@22:%2Eleading.example\"=\"0x322b390462b441b639beb9a19d6300e7ade71eae06a35e321b45e5cbff5162e8,0x62ab4ac5f52743d13ef4a429b5f1651f244ea3deef0d01aa7cdfa27ef3ae3eb3\"
\"ecdsa-sha2-nistp256@2200:db.example.com\"=\"nistp256,0x9794c6f233189bebff4ea72308b79f96d10462215658f9573b8be4cde73d7f31,0xb90a8eb71af2f8cf0401296a217e9eb450126272973ae54d79c5cc8150c42906\"
";
        std::fs::write(&source_path, encode_utf16le_with_bom(registry_export))
            .expect("registry export should be written");

        let result = import_putty_host_keys(&source_path, &destination_path, false)
            .expect("registry export import should work");

        assert_eq!(result.imported, 2);
        assert_eq!(result.skipped_blank_or_comment, 2);
        assert_eq!(result.skipped_outside_target, 3);
        assert_eq!(result.skipped_malformed, 0);
        assert_eq!(result.skipped_unsupported_key_type, 0);

        assert_eq!(
            load_known_host_keys(&destination_path, ".leading.example", 22)
                .expect("escaped registry hostname should load")
                .len(),
            1
        );
        assert_eq!(
            load_known_host_keys(&destination_path, "db.example.com", 2200)
                .expect("non-default port registry host should load")
                .len(),
            1
        );
    }

    #[test]
    fn import_putty_host_keys_dry_run_reports_without_writing_destination() {
        let workspace = temporary_workspace();
        let source_path = workspace.join("sshhostkeys");
        let destination_path = workspace.join("known_hosts");

        std::fs::write(
            &source_path,
            "ssh-ed25519@22:example.com 0x322b390462b441b639beb9a19d6300e7ade71eae06a35e321b45e5cbff5162e8,0x62ab4ac5f52743d13ef4a429b5f1651f244ea3deef0d01aa7cdfa27ef3ae3eb3\n",
        )
        .expect("sshhostkeys source should be written");

        let result = import_putty_host_keys(&source_path, &destination_path, true)
            .expect("dry-run PuTTY host-key import should work");

        assert_eq!(result.imported, 1);
        assert!(!destination_path.exists());
    }

    fn sample_key() -> PublicKey {
        PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("sample key should parse")
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
        let path = std::env::temp_dir().join(format!("rustty-known-hosts-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
