//! Reusable transport primitives for RusTTY tools.

mod ssh;

pub use ssh::{HostKeyCheck, SshExecRequest, SshExecResult, TransportError, execute_ssh_command};
