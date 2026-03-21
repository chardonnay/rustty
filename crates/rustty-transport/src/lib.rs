//! Reusable transport primitives for RusTTY tools.

mod ssh;

pub use ssh::{
    HostKeyCheck, SshAuthentication, SshDynamicForwardSpec, SshExecRequest, SshExecResult,
    SshLocalForwardSpec, SshRemoteForwardSpec, SshShellRequest, SshShellResult, TerminalSize,
    TransportError, VerifiedHostKey, VerifiedHostKeySource, execute_ssh_command,
    host_key_fingerprint, probe_ssh_host_key, run_interactive_shell,
};
