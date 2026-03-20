//! Versioned RusTTY configuration schema, path resolution, and persistence.

mod error;
mod known_hosts;
mod model;
mod paths;
mod store;

pub use error::{ConfigError, ValidationError};
pub use known_hosts::{
    KnownHostKey, PersistKnownHostResult, load_known_host_keys, persist_known_host_key,
};
pub use model::{
    AppConfig, CURRENT_SCHEMA_VERSION, ImportSource, SessionStore, StoredSession, ToolProfile,
};
pub use paths::{default_config_path, default_known_hosts_path};
pub use store::{InitResult, init_config, load_config, save_config};
