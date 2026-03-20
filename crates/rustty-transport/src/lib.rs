//! Reusable transport primitives for RusTTY tools.

mod ssh;

pub use ssh::{
    HostKeyCheck, SshAuthentication, SshExecRequest, SshExecResult, SshShellRequest,
    SshShellResult, TerminalSize, TransportError, VerifiedHostKey, VerifiedHostKeySource,
    execute_ssh_command, run_interactive_shell,
};
