//! Filesystem-backed RusTTY configuration persistence helpers.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{AppConfig, ConfigError};

/// Result of initializing a config file on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitResult {
    /// Config path that was requested.
    pub path: PathBuf,
    /// Whether a new file was created.
    pub created: bool,
}

/// Loads and validates a RusTTY config file.
pub fn load_config(path: impl AsRef<Path>) -> Result<AppConfig, ConfigError> {
    let path = path.as_ref().to_path_buf();
    let input = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    let config = AppConfig::from_toml_str(&input).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    config
        .validate()
        .map_err(ConfigError::Validation)
        .map(|()| config)
}

/// Saves a RusTTY config file, creating parent directories when needed.
pub fn save_config(path: impl AsRef<Path>, config: &AppConfig) -> Result<(), ConfigError> {
    config.validate().map_err(ConfigError::Validation)?;

    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let output = config.to_toml_string().map_err(ConfigError::Serialize)?;
    fs::write(&path, output).map_err(|source| ConfigError::Io { path, source })
}

/// Creates a sample config file if one does not already exist.
pub fn init_config(path: impl AsRef<Path>) -> Result<InitResult, ConfigError> {
    let path = path.as_ref().to_path_buf();
    if path.exists() {
        let _ = load_config(&path)?;
        return Ok(InitResult {
            path,
            created: false,
        });
    }

    let config = AppConfig::sample();
    save_config(&path, &config)?;
    Ok(InitResult {
        path,
        created: true,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rustty_core::{Protocol, SessionConfig};

    use super::{ConfigError, InitResult, init_config, load_config, save_config};
    use crate::{AppConfig, StoredSession, error::ValidationError};

    #[test]
    fn save_and_load_round_trip() {
        let workspace = temporary_workspace();
        let path = workspace.join("config.toml");
        let mut config = AppConfig::sample();
        config.add_session(StoredSession::new(
            SessionConfig::new("serial-lab", Protocol::Serial).with_host("ttyUSB0"),
        ));

        save_config(&path, &config).expect("config should save");
        let loaded = load_config(&path).expect("config should load");
        assert_eq!(loaded, config);
    }

    #[test]
    fn init_config_creates_sample_file_once() {
        let workspace = temporary_workspace();
        let path = workspace.join("config.toml");

        let first = init_config(&path).expect("first init should create the config");
        let second = init_config(&path).expect("second init should validate the existing config");

        assert_eq!(
            first,
            InitResult {
                path: path.clone(),
                created: true,
            }
        );
        assert_eq!(
            second,
            InitResult {
                path,
                created: false,
            }
        );
    }

    #[test]
    fn save_rejects_invalid_config() {
        let workspace = temporary_workspace();
        let path = workspace.join("config.toml");
        let mut config = AppConfig::sample();
        config.product_name.clear();

        let error = save_config(&path, &config).expect_err("invalid config should be rejected");
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::EmptyProductName)
        ));
    }

    fn temporary_workspace() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustty-config-test-{nonce}"));
        std::fs::create_dir_all(&path).expect("temporary workspace should be created");
        path
    }
}
