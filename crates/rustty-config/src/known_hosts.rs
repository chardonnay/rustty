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

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ssh_key::PublicKey;

    use super::{load_known_host_keys, persist_known_host_key};

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
