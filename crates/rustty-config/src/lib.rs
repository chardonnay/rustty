//! Versioned RusTTY configuration schema, path resolution, and persistence.

mod error;
mod model;
mod paths;
mod store;

pub use error::{ConfigError, ValidationError};
pub use model::{
    AppConfig, CURRENT_SCHEMA_VERSION, ImportSource, SessionStore, StoredSession, ToolProfile,
};
pub use paths::default_config_path;
pub use store::{InitResult, init_config, load_config, save_config};
