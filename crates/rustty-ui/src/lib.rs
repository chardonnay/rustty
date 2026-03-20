//! UI-facing bootstrap helpers for the RusTTY GUI application.

use rustty_core::{ToolSpec, product::PRODUCT_NAME};

/// A minimal placeholder UI surface for the RusTTY bootstrap phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapWindow {
    /// Window title or primary heading.
    pub title: String,
    /// Long-form explanatory text.
    pub body: String,
}

/// Builds a placeholder window description for the GUI client.
#[must_use]
pub fn placeholder_window(tool: ToolSpec) -> BootstrapWindow {
    BootstrapWindow {
        title: format!("{PRODUCT_NAME} bootstrap"),
        body: format!(
            "{summary}\n\nThis placeholder keeps the GUI entry point wired into \
             the shared workspace while the real client is implemented.\nManual: \
             {manual}\nChangelog: {changelog}",
            summary = tool.bootstrap_message(),
            manual = tool.doc_path,
            changelog = tool.changelog_path,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::placeholder_window;
    use rustty_core::{ToolKind, tool_spec};

    #[test]
    fn bootstrap_window_mentions_manual() {
        let window = placeholder_window(tool_spec(ToolKind::Rustty));
        assert!(window.body.contains("docs/tools/rustty.adoc"));
    }
}
