//! Shared tool metadata for RusTTY binaries and repository checks.

use crate::session::Protocol;

const RUSTTY_PROTOCOLS: &[Protocol] = &[
    Protocol::Ssh,
    Protocol::Scp,
    Protocol::Sftp,
    Protocol::Telnet,
    Protocol::Raw,
    Protocol::Rlogin,
    Protocol::Serial,
];
const RUSPLINK_PROTOCOLS: &[Protocol] = &[Protocol::Ssh];
const RUSCP_PROTOCOLS: &[Protocol] = &[Protocol::Scp];
const RUSFTP_PROTOCOLS: &[Protocol] = &[Protocol::Sftp];
const RUSAGENT_PROTOCOLS: &[Protocol] = &[Protocol::Agent];
const RUSTTYGEN_PROTOCOLS: &[Protocol] = &[Protocol::Keygen];

/// Known first-party RusTTY tools.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ToolKind {
    /// GUI terminal client.
    Rustty,
    /// CLI SSH client.
    Rusplink,
    /// SCP client.
    Ruscp,
    /// SFTP client.
    Rusftp,
    /// SSH agent.
    Rusagent,
    /// Key generator and converter.
    Rusttygen,
}

/// Static metadata describing a RusTTY binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolSpec {
    /// Tool identity.
    pub kind: ToolKind,
    /// On-disk binary name.
    pub binary_name: &'static str,
    /// User-facing display name.
    pub display_name: &'static str,
    /// PuTTY tool names replaced by this binary.
    pub replaces: &'static [&'static str],
    /// Primary documentation path.
    pub doc_path: &'static str,
    /// Per-tool changelog path.
    pub changelog_path: &'static str,
    /// Primary supported protocol families.
    pub protocols: &'static [Protocol],
    /// One-line tool summary.
    pub purpose: &'static str,
}

impl ToolSpec {
    /// Renders a consistent bootstrap banner for placeholder binaries.
    #[must_use]
    pub fn bootstrap_message(self) -> String {
        format!(
            "{name} bootstrap\n\nPurpose: {purpose}\nReplaces: {replaces}\nProtocols: {protocols}\nManual: {manual}\nChangelog: {changelog}",
            name = self.display_name,
            purpose = self.purpose,
            replaces = self.replaces.join(", "),
            protocols = join_protocols(self.protocols),
            manual = self.doc_path,
            changelog = self.changelog_path,
        )
    }

    /// Returns whether the tool covers a protocol.
    #[must_use]
    pub fn supports_protocol(self, protocol: Protocol) -> bool {
        self.protocols.contains(&protocol)
    }
}

/// Metadata for the `rustty` binary.
pub const RUSTTY: ToolSpec = ToolSpec {
    kind: ToolKind::Rustty,
    binary_name: "rustty",
    display_name: "RusTTY",
    replaces: &["putty"],
    doc_path: "docs/tools/rustty.adoc",
    changelog_path: "docs/changelogs/rustty.adoc",
    protocols: RUSTTY_PROTOCOLS,
    purpose: "Cross-platform GUI terminal client and session launcher.",
};

/// Metadata for the `rusplink` binary.
pub const RUSPLINK: ToolSpec = ToolSpec {
    kind: ToolKind::Rusplink,
    binary_name: "rusplink",
    display_name: "RusPlink",
    replaces: &["plink"],
    doc_path: "docs/tools/rusplink.adoc",
    changelog_path: "docs/changelogs/rusplink.adoc",
    protocols: RUSPLINK_PROTOCOLS,
    purpose: "Command-line SSH client for remote execution and forwarding.",
};

/// Metadata for the `ruscp` binary.
pub const RUSCP: ToolSpec = ToolSpec {
    kind: ToolKind::Ruscp,
    binary_name: "ruscp",
    display_name: "RusCP",
    replaces: &["pscp"],
    doc_path: "docs/tools/ruscp.adoc",
    changelog_path: "docs/changelogs/ruscp.adoc",
    protocols: RUSCP_PROTOCOLS,
    purpose: "Secure copy client for scripted and interactive transfers.",
};

/// Metadata for the `rusftp` binary.
pub const RUSFTP: ToolSpec = ToolSpec {
    kind: ToolKind::Rusftp,
    binary_name: "rusftp",
    display_name: "RusFTP",
    replaces: &["psftp"],
    doc_path: "docs/tools/rusftp.adoc",
    changelog_path: "docs/changelogs/rusftp.adoc",
    protocols: RUSFTP_PROTOCOLS,
    purpose: "SFTP client for interactive and batch file transfer.",
};

/// Metadata for the `rusagent` binary.
pub const RUSAGENT: ToolSpec = ToolSpec {
    kind: ToolKind::Rusagent,
    binary_name: "rusagent",
    display_name: "RusAgent",
    replaces: &["pageant"],
    doc_path: "docs/tools/rusagent.adoc",
    changelog_path: "docs/changelogs/rusagent.adoc",
    protocols: RUSAGENT_PROTOCOLS,
    purpose: "SSH authentication agent and key broker.",
};

/// Metadata for the `rusttygen` binary.
pub const RUSTTYGEN: ToolSpec = ToolSpec {
    kind: ToolKind::Rusttygen,
    binary_name: "rusttygen",
    display_name: "RusTTYgen",
    replaces: &["puttygen"],
    doc_path: "docs/tools/rusttygen.adoc",
    changelog_path: "docs/changelogs/rusttygen.adoc",
    protocols: RUSTTYGEN_PROTOCOLS,
    purpose: "Key generation, conversion, and inspection tool.",
};

/// All first-party RusTTY tools.
pub const ALL_TOOLS: [ToolSpec; 6] = [RUSTTY, RUSPLINK, RUSCP, RUSFTP, RUSAGENT, RUSTTYGEN];

/// Returns the metadata for a tool kind.
#[must_use]
pub const fn tool_spec(kind: ToolKind) -> ToolSpec {
    match kind {
        ToolKind::Rustty => RUSTTY,
        ToolKind::Rusplink => RUSPLINK,
        ToolKind::Ruscp => RUSCP,
        ToolKind::Rusftp => RUSFTP,
        ToolKind::Rusagent => RUSAGENT,
        ToolKind::Rusttygen => RUSTTYGEN,
    }
}

fn join_protocols(protocols: &[Protocol]) -> String {
    protocols
        .iter()
        .map(|protocol| protocol.label())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{ALL_TOOLS, RUSTTY, ToolKind, tool_spec};
    use crate::session::Protocol;

    #[test]
    fn all_doc_paths_are_unique() {
        let mut paths = ALL_TOOLS
            .iter()
            .map(|tool| tool.doc_path)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), ALL_TOOLS.len());
    }

    #[test]
    fn rustty_supports_serial() {
        assert!(RUSTTY.supports_protocol(Protocol::Serial));
    }

    #[test]
    fn tool_lookup_returns_expected_binary() {
        assert_eq!(tool_spec(ToolKind::Rusftp).binary_name, "rusftp");
    }
}
