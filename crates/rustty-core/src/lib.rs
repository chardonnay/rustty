//! Shared types and metadata for the RusTTY workspace.

pub mod product;
pub mod session;
pub mod tools;

pub use product::{
    BOOTSTRAP_BRANCH, DEFAULT_BRANCH, NEXT_RELEASE_NOTES_PATH, PRODUCT_NAME, REPOSITORY_SLUG,
    REPOSITORY_URL, SUITE_CHANGELOG_PATH,
};
pub use session::{HostKeyPolicy, PortForwardSpec, Protocol, SessionConfig, StorageFormat};
pub use tools::{ALL_TOOLS, ToolKind, ToolSpec, tool_spec};
