//! Versioned RusTTY configuration schema, path resolution, and persistence.

mod error;
mod known_hosts;
mod model;
mod paths;
mod putty_sessions;
mod store;
mod text;

pub use error::{ConfigError, ValidationError};
pub use known_hosts::{
    ImportKnownHostsResult, ImportPuttyHostKeysResult, KnownHostKey, PersistKnownHostResult,
    import_known_hosts, import_putty_host_keys, load_known_host_keys, persist_known_host_key,
};
pub use model::{
    AppConfig, CURRENT_SCHEMA_VERSION, ImportSource, SessionStore, StoredSession, ToolProfile,
};
pub use paths::{default_agent_socket_path, default_config_path, default_known_hosts_path};
pub use putty_sessions::{ImportPuttySessionsResult, import_putty_sessions};
pub use store::{InitResult, init_config, load_config, save_config};
