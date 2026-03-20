use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--print-sample-config")
    {
        return match rustty_config::AppConfig::sample().to_toml_string() {
            Ok(config) => {
                print!("{config}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to render sample config: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let window =
        rustty_ui::placeholder_window(rustty_core::tool_spec(rustty_core::ToolKind::Rustty));
    println!("{}\n\n{}", window.title, window.body);
    ExitCode::SUCCESS
}
