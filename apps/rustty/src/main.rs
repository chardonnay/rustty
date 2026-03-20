fn main() {
    let window =
        rustty_ui::placeholder_window(rustty_core::tool_spec(rustty_core::ToolKind::Rustty));
    println!("{}\n\n{}", window.title, window.body);
}
