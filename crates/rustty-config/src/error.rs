//! Error types for RusTTY configuration loading, saving, and validation.

use std::{fmt, io, path::PathBuf};

/// Errors returned by RusTTY configuration operations.
#[derive(Debug)]
pub enum ConfigError {
    /// Required platform configuration directory information is unavailable.
    MissingConfigBaseDir {
        /// Current platform label.
        platform: &'static str,
        /// Required environment variable or source.
        source: &'static str,
    },
    /// A filesystem operation failed.
    Io {
        /// Path that was being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A TOML document could not be parsed.
    Parse {
        /// Path of the parsed document.
        path: PathBuf,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// A TOML document could not be serialized.
    Serialize(toml::ser::Error),
    /// The loaded configuration failed validation.
    Validation(ValidationError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfigBaseDir { platform, source } => write!(
                formatter,
                "cannot determine RusTTY config directory on {platform}; missing {source}"
            ),
            Self::Io { path, source } => {
                write!(formatter, "{}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "{}: {source}", path.display())
            }
            Self::Serialize(source) => write!(formatter, "{source}"),
            Self::Validation(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingConfigBaseDir { .. } => None,
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize(source) => Some(source),
            Self::Validation(source) => Some(source),
        }
    }
}

/// Validation failures for RusTTY config documents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// The serialized schema version does not match the current one.
    UnsupportedSchemaVersion(u32),
    /// The product name is missing.
    EmptyProductName,
    /// The product name does not match RusTTY.
    UnexpectedProductName(String),
    /// A session name is missing.
    EmptySessionName,
    /// The config repeats a tool profile binary name.
    DuplicateToolBinary(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported RusTTY schema version: {version}")
            }
            Self::EmptyProductName => {
                write!(formatter, "RusTTY config product_name must not be empty")
            }
            Self::UnexpectedProductName(name) => {
                write!(formatter, "unexpected RusTTY product_name: {name}")
            }
            Self::EmptySessionName => write!(formatter, "RusTTY session names must not be empty"),
            Self::DuplicateToolBinary(binary_name) => {
                write!(formatter, "duplicate RusTTY tool profile: {binary_name}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}
