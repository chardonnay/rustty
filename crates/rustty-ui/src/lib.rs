//! Shared native GUI launcher support for the RusTTY desktop client.

mod app;
mod model;

pub use app::run_native;
pub use model::{LauncherModel, LauncherOptions};
