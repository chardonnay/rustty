//! OpenSSH-style known-hosts lookup and append-only persistence for RusTTY.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ssh_key::{
    PublicKey,
    known_hosts::{Entry, HostPatterns},
};

use crate::ConfigError;

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
    trimmed.is_empty() || trimmed.starts_with('#')
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

    use super::{import_known_hosts, load_known_host_keys, persist_known_host_key};

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

    fn sample_key() -> PublicKey {
        PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("sample key should parse")
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
