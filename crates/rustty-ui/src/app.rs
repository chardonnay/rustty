//! Native egui application shell for the RusTTY launcher.

use std::time::Duration;

use eframe::{
    App, CreationContext, NativeOptions,
    egui::{
        self, Align, Color32, ComboBox, Context, Frame, Grid, Layout, Margin, RichText, ScrollArea,
        Stroke, TopBottomPanel, Vec2, ViewportBuilder,
    },
};
use rustty_config::StoredSession;
use rustty_core::{ALL_TOOLS, PRODUCT_NAME, Protocol};
use rustty_transport::TerminalSize;

use crate::model::{
    CommandRunnerState, InteractiveShellState, LauncherModel, LauncherOptions, LauncherView,
    SessionEditorDraft, TerminalTranscriptEntry, TerminalTranscriptTone, TerminalWindowSnapshot,
    host_key_policy_label, import_source_label, session_launch_preview, storage_format_label,
};

/// Runs the native RusTTY launcher window.
pub fn run_native(options: LauncherOptions) -> Result<(), String> {
    let native_options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1240.0, 820.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        &format!("{PRODUCT_NAME} Launcher"),
        native_options,
        Box::new(move |creation_context| {
            Ok(Box::new(RusttyApp::new(creation_context, options.clone())))
        }),
    )
    .map_err(|error| format!("failed to open {PRODUCT_NAME} GUI: {error}"))
}

struct RusttyApp {
    model: LauncherModel,
}

impl RusttyApp {
    fn new(creation_context: &CreationContext<'_>, options: LauncherOptions) -> Self {
        configure_visuals(&creation_context.egui_ctx);
        Self {
            model: LauncherModel::load(options),
        }
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(RichText::new(PRODUCT_NAME).size(28.0).strong());
            ui.label(
                RichText::new("Native session launcher")
                    .size(15.0)
                    .color(Color32::from_rgb(110, 73, 56)),
            );
            ui.add_space(16.0);

            if ui.button("Reload config").clicked() {
                self.model.reload();
            }

            if ui.button("Ensure sample config").clicked() {
                if let Err(error) = self.model.initialize_sample_config() {
                    self.model.set_status_message(error);
                }
            }

            if self.model.has_hidden_terminal_window()
                && ui.button("Show terminal window").clicked()
            {
                let _ = self.model.show_terminal_window();
            }

            if ui.button("Copy config path").clicked() {
                copy_text(
                    ui.ctx(),
                    self.model.options().config_path.display().to_string(),
                    &mut self.model,
                    "Copied config path to clipboard",
                );
            }

            if ui.button("Copy known-hosts path").clicked() {
                copy_text(
                    ui.ctx(),
                    self.model.options().known_hosts_path.display().to_string(),
                    &mut self.model,
                    "Copied known-hosts path to clipboard",
                );
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(self.model.status_message()).color(Color32::from_rgb(95, 70, 58)),
                );
            });
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            for view in [
                LauncherView::Sessions,
                LauncherView::Tools,
                LauncherView::About,
            ] {
                let selected = self.model.view() == view;
                if ui.selectable_label(selected, view.label()).clicked() {
                    self.model.set_view(view);
                }
            }
        });
    }

    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.heading("Workspace");
        ui.label(self.model.config_summary());
        ui.add_space(8.0);

        stats_card(ui, &self.model);

        if self.model.view() != LauncherView::Sessions {
            return;
        }

        ui.separator();
        ui.label("Filter sessions");
        ui.text_edit_singleline(self.model.filter_text_mut());
        ui.add_space(8.0);

        let filtered_sessions = self.model.filtered_sessions();
        if filtered_sessions.is_empty() {
            ui.label(
                RichText::new("No sessions match the current filter.")
                    .italics()
                    .color(Color32::from_rgb(118, 92, 78)),
            );
            return;
        }

        ScrollArea::vertical()
            .id_salt("rustty-session-list")
            .show(ui, |ui| {
                for stored_session in filtered_sessions {
                    let selected = self
                        .model
                        .selected_session()
                        .is_some_and(|selected_session| {
                            selected_session.session.name == stored_session.session.name
                        });

                    let summary = session_endpoint(&stored_session);
                    let imported = stored_session
                        .imported_from
                        .map(import_source_label)
                        .unwrap_or("RusTTY native");

                    Frame::group(ui.style())
                        .fill(if selected {
                            Color32::from_rgb(233, 220, 206)
                        } else {
                            Color32::from_rgb(244, 237, 228)
                        })
                        .stroke(Stroke::new(1.0, Color32::from_rgb(216, 203, 189)))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            if ui
                                .selectable_label(
                                    selected,
                                    RichText::new(&stored_session.session.name).strong(),
                                )
                                .clicked()
                            {
                                self.model.select_session(&stored_session.session.name);
                            }

                            ui.horizontal_wrapped(|ui| {
                                protocol_badge(ui, stored_session.session.protocol);
                                ui.label(summary);
                            });
                            ui.label(
                                RichText::new(imported)
                                    .size(12.0)
                                    .color(Color32::from_rgb(108, 81, 67)),
                            );
                        });
                    ui.add_space(6.0);
                }
            });
    }

    fn render_sessions_view(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical()
            .id_salt("rustty-sessions-view")
            .show(ui, |ui| {
                if self.model.config_is_missing() {
                    empty_state_card(
                        ui,
                        "No RusTTY config yet",
                        "Create a real session below, import PuTTY sessions, or bootstrap a sample config from the toolbar.",
                    );
                } else if let Some(error) = self.model.config_error() {
                    empty_state_card(
                        ui,
                        "Config needs attention",
                        &format!("The launcher opened, but config loading failed: {error}"),
                    );
                }

                self.render_session_editor(ui);
                ui.add_space(14.0);
                self.render_putty_import(ui);

                if let Some(stored_session) = self.model.selected_session() {
                    ui.add_space(14.0);
                    self.render_selected_session(ui, &stored_session);
                } else if self.model.has_loaded_config() {
                    ui.add_space(14.0);
                    empty_state_card(
                        ui,
                        "No saved session selected",
                        "Use the left-hand list to inspect saved sessions, or keep working in the editor to create the next one.",
                    );
                }

                ui.add_space(14.0);
                self.render_quick_connect(ui);
            });
    }

    fn render_session_editor(&mut self, ui: &mut egui::Ui) {
        section_card(ui, "Session editor", |ui| {
            let selected_session_exists = self.model.selected_session().is_some();
            let is_editing_existing = self.model.session_editor().is_editing_existing_session();
            let imported_from = self.model.session_editor().imported_from;
            let mut start_new = false;
            let mut reload_selected = false;
            let mut save_session = false;
            let mut delete_selected = false;

            ui.horizontal_wrapped(|ui| {
                start_new = ui.button("New session").clicked();
                reload_selected = ui
                    .add_enabled(
                        selected_session_exists,
                        egui::Button::new("Load selected into editor"),
                    )
                    .clicked();
                save_session = ui.button("Save session").clicked();
                delete_selected = ui
                    .add_enabled(
                        is_editing_existing && selected_session_exists,
                        egui::Button::new("Delete selected session"),
                    )
                    .clicked();
            });

            if start_new {
                self.model.start_new_session_draft();
            }
            if reload_selected {
                if let Err(error) = self.model.load_editor_from_selected_session() {
                    self.model.set_status_message(error);
                }
            }
            if save_session {
                if let Err(error) = self.model.save_session_editor() {
                    self.model.set_status_message(error);
                }
            }
            if delete_selected {
                if let Err(error) = self.model.delete_selected_session() {
                    self.model.set_status_message(error);
                }
            }

            ui.add_space(8.0);
            ui.label(
                RichText::new(if is_editing_existing {
                    "Editing the currently selected saved session. Save writes directly to the RusTTY config file."
                } else {
                    "Creating a new saved session. Save will create the RusTTY config file if it does not exist yet."
                })
                .color(Color32::from_rgb(102, 77, 64)),
            );
            if let Some(import_source) = imported_from {
                ui.label(
                    RichText::new(format!(
                        "Imported provenance: {}",
                        import_source_label(import_source)
                    ))
                    .color(Color32::from_rgb(108, 79, 64)),
                );
            }

            let preview = {
                let draft = self.model.session_editor_mut();
                render_session_editor_form(ui, draft)
            };

            ui.add_space(10.0);
            ui.label(RichText::new("Save preview").strong());
            code_block(ui, &preview);
        });
    }

    fn render_putty_import(&mut self, ui: &mut egui::Ui) {
        section_card(ui, "PuTTY import", |ui| {
            ui.label(
                RichText::new(
                    "Import a PuTTY registry export, a Unix PuTTY session file, or a `sessions/` directory directly into the RusTTY config shown by this launcher.",
                )
                .color(Color32::from_rgb(102, 77, 64)),
            );

            ui.add_space(8.0);
            Grid::new("rustty-putty-import-grid")
                .num_columns(2)
                .spacing(Vec2::new(16.0, 8.0))
                .show(ui, |ui| {
                    ui.label("Source path");
                    ui.text_edit_singleline(self.model.putty_import_path_mut());
                    ui.end_row();
                });

            let mut dry_run = false;
            let mut import_now = false;
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                dry_run = ui.button("Dry-run import").clicked();
                import_now = ui.button("Import into config").clicked();
            });

            if dry_run {
                if let Err(error) = self.model.import_putty_sessions_from_editor(true) {
                    self.model.set_status_message(error);
                }
            }
            if import_now {
                if let Err(error) = self.model.import_putty_sessions_from_editor(false) {
                    self.model.set_status_message(error);
                }
            }

            if let Some(report) = self.model.putty_import_report() {
                ui.add_space(10.0);
                ui.label(RichText::new("Last import report").strong());
                code_block(ui, report);
            }
        });
    }

    fn render_selected_session(&mut self, ui: &mut egui::Ui, stored_session: &StoredSession) {
        let session = &stored_session.session;
        let launch_preview = session_launch_preview(stored_session);

        section_card(ui, "Selected session", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(&session.name);
                protocol_badge(ui, session.protocol);
                ui.label(
                    RichText::new(session_endpoint(stored_session))
                        .color(Color32::from_rgb(99, 73, 60)),
                );
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Copy launch preview").clicked() {
                    copy_text(
                        ui.ctx(),
                        launch_preview.clone(),
                        &mut self.model,
                        format!("Copied launch preview for '{}'", session.name),
                    );
                }
                if ui.button("Use as quick-connect draft").clicked() {
                    let _ = self.model.populate_draft_from_selected_session();
                }
            });

            ui.add_space(10.0);
            Grid::new("rustty-session-details")
                .num_columns(2)
                .spacing(Vec2::new(16.0, 8.0))
                .show(ui, |ui| {
                    detail_row(ui, "Host", session.host.as_deref().unwrap_or("n/a"));
                    detail_row(
                        ui,
                        "Port",
                        &session
                            .effective_port()
                            .map(|port| port.to_string())
                            .unwrap_or_else(|| "n/a".to_owned()),
                    );
                    detail_row(ui, "Username", session.username.as_deref().unwrap_or("n/a"));
                    detail_row(ui, "Storage", storage_format_label(session.saved_in));
                    detail_row(
                        ui,
                        "Host-key policy",
                        host_key_policy_label(session.host_key_policy),
                    );
                    detail_row(
                        ui,
                        "Imported from",
                        stored_session
                            .imported_from
                            .map(import_source_label)
                            .unwrap_or("RusTTY native"),
                    );
                    detail_row(
                        ui,
                        "Password env",
                        session.password_env.as_deref().unwrap_or("n/a"),
                    );
                    detail_row(
                        ui,
                        "Private key",
                        session.private_key_path.as_deref().unwrap_or("n/a"),
                    );
                    detail_row(
                        ui,
                        "Key passphrase env",
                        session.key_passphrase_env.as_deref().unwrap_or("n/a"),
                    );
                    detail_row(
                        ui,
                        "Keyboard-interactive env",
                        session.keyboard_interactive_env.as_deref().unwrap_or("n/a"),
                    );
                });

            ui.add_space(12.0);
            ui.label(RichText::new("Forwarding").strong());
            ui.label(format!(
                "Local: {}  Remote: {}  Dynamic: {}",
                session.port_forwards.len(),
                session.remote_forwards.len(),
                session.dynamic_forwards.len()
            ));
            for forward in &session.port_forwards {
                ui.label(format!("Local {} -> {}", forward.source, forward.target));
            }
            for forward in &session.remote_forwards {
                ui.label(format!("Remote {} -> {}", forward.source, forward.target));
            }
            for forward in &session.dynamic_forwards {
                ui.label(format!("Dynamic {}", forward.listen));
            }
            if session.port_forwards.is_empty()
                && session.remote_forwards.is_empty()
                && session.dynamic_forwards.is_empty()
            {
                ui.label(
                    RichText::new("No forwarding rules saved for this session.")
                        .italics()
                        .color(Color32::from_rgb(118, 92, 78)),
                );
            }

            if let Some(notes) = &stored_session.notes {
                ui.add_space(12.0);
                ui.label(RichText::new("Migration notes").strong());
                ui.label(notes);
            }

            ui.add_space(12.0);
            ui.label(RichText::new("Launch preview").strong());
            code_block(ui, &launch_preview);

            ui.add_space(12.0);
            self.render_session_terminal_launcher(ui, stored_session);
        });
    }

    fn render_session_terminal_launcher(
        &mut self,
        ui: &mut egui::Ui,
        stored_session: &StoredSession,
    ) {
        ui.label(RichText::new("Terminal window").strong());
        ui.add_space(6.0);

        ui.label(
            RichText::new(
                "Open a dedicated session window for this saved session. SSH sessions can already run non-interactive commands there with transcript history and GUI-side host-key confirmation.",
            )
            .color(Color32::from_rgb(102, 77, 64)),
        );

        ui.add_space(8.0);
        let terminal_snapshot = self.model.terminal_window_snapshot();
        let is_current_terminal = terminal_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.session_name == stored_session.session.name);
        ui.horizontal_wrapped(|ui| {
            let button_label = if is_current_terminal {
                "Show terminal window"
            } else {
                "Open terminal window"
            };
            if ui.button(button_label).clicked() {
                if let Err(error) = self.model.open_selected_session_terminal_window() {
                    self.model.set_status_message(error);
                }
            }
            if stored_session.session.protocol != Protocol::Ssh {
                ui.label(
                    RichText::new(
                        "Interactive GUI transport for this protocol is still queued after the first SSH-backed terminal window milestone.",
                    )
                    .italics()
                    .color(Color32::from_rgb(118, 92, 78)),
                );
            }
        });

        if let Some(snapshot) = terminal_snapshot
            .filter(|snapshot| snapshot.session_name == stored_session.session.name)
        {
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!(
                    "Current window state: {}",
                    terminal_state_label(&snapshot.command_runner_state)
                ))
                .color(Color32::from_rgb(108, 79, 64)),
            );
            if !snapshot.visible {
                ui.label(
                    RichText::new(
                        "The terminal window is currently hidden. Reopen it to continue with host-key prompts or review the transcript.",
                    )
                    .italics()
                    .color(Color32::from_rgb(118, 92, 78)),
                );
            }
        }
    }

    fn render_quick_connect(&mut self, ui: &mut egui::Ui) {
        section_card(ui, "Quick connect draft", |ui| {
            let draft = self.model.quick_connect_mut();

            ui.horizontal_wrapped(|ui| {
                ui.label("Protocol");
                ComboBox::from_id_salt("rustty-quick-connect-protocol")
                    .selected_text(draft.protocol.label())
                    .show_ui(ui, |ui| {
                        for protocol in [
                            Protocol::Ssh,
                            Protocol::Telnet,
                            Protocol::Raw,
                            Protocol::Rlogin,
                            Protocol::Serial,
                        ] {
                            ui.selectable_value(&mut draft.protocol, protocol, protocol.label());
                        }
                    });
            });

            Grid::new("rustty-quick-connect-grid")
                .num_columns(2)
                .spacing(Vec2::new(16.0, 8.0))
                .show(ui, |ui| {
                    ui.label("Draft name");
                    ui.text_edit_singleline(&mut draft.name);
                    ui.end_row();

                    ui.label("Host / endpoint");
                    ui.text_edit_singleline(&mut draft.host);
                    ui.end_row();

                    ui.label("Port");
                    ui.text_edit_singleline(&mut draft.port);
                    ui.end_row();

                    ui.label("Username");
                    ui.text_edit_singleline(&mut draft.username);
                    ui.end_row();
                });

            let preview = self.model.quick_connect().preview();
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Copy draft preview").clicked() {
                    copy_text(
                        ui.ctx(),
                        preview.clone(),
                        &mut self.model,
                        "Copied quick-connect launch preview",
                    );
                }
                ui.label(
                    RichText::new(
                        "This draft is still a launcher-side planning aid. Real saved-session editing now lives in the session editor above, while ad-hoc GUI transport remains queued.",
                    )
                    .italics()
                    .color(Color32::from_rgb(112, 85, 70)),
                );
            });

            ui.add_space(8.0);
            code_block(ui, &preview);
        });
    }

    fn render_tools_view(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical()
            .id_salt("rustty-tools-view")
            .show(ui, |ui| {
                for tool in ALL_TOOLS {
                    section_card(ui, tool.display_name, |ui| {
                        ui.label(tool.purpose);
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("Binary: {}", tool.binary_name)).strong(),
                            );
                            ui.label(format!("Replaces: {}", tool.replaces.join(", ")));
                        });
                        ui.horizontal_wrapped(|ui| {
                            for protocol in tool.protocols {
                                protocol_badge(ui, *protocol);
                            }
                        });
                        ui.add_space(8.0);
                        ui.label(format!("Manual: {}", tool.doc_path));
                        ui.label(format!("Changelog: {}", tool.changelog_path));
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Copy manual path").clicked() {
                                copy_text(
                                    ui.ctx(),
                                    tool.doc_path.to_owned(),
                                    &mut self.model,
                                    format!("Copied manual path for {}", tool.display_name),
                                );
                            }
                            if ui.button("Copy changelog path").clicked() {
                                copy_text(
                                    ui.ctx(),
                                    tool.changelog_path.to_owned(),
                                    &mut self.model,
                                    format!("Copied changelog path for {}", tool.display_name),
                                );
                            }
                        });
                    });
                    ui.add_space(10.0);
                }
            });
    }

    fn render_about_view(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical()
            .id_salt("rustty-about-view")
            .show(ui, |ui| {
                section_card(ui, "Launcher status", |ui| {
                    ui.label(
                        "This is the first real native RusTTY GUI client. It loads RusTTY config data, surfaces migrated PuTTY sessions, and gives operators a desktop place to review launch plans, diagnostics, and saved-session command transcripts.",
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "RusTTY now opens a dedicated saved-session terminal window for the first SSH-backed GUI workflow. Full interactive terminal emulation, scrollback behavior, resize handling, and non-SSH GUI transports are still queued in the next milestones.",
                        )
                        .color(Color32::from_rgb(108, 79, 64)),
                    );
                });

                section_card(ui, "Current GUI scope", |ui| {
                    for line in [
                        "Native launcher window with session browser, session editor, and quick-connect draft",
                        "Config-state diagnostics, sample-config creation, session persistence, and path copy actions",
                        "PuTTY session import from registry exports, session files, and sessions directories",
                        "Dedicated saved-session terminal window with transcript history and host-key confirmation",
                        "Inspection of saved auth defaults, forwarding, and import provenance",
                        "Tool catalog with manual and changelog path discovery",
                    ] {
                        ui.label(format!("• {line}"));
                    }
                });

                section_card(ui, "Next terminal milestones", |ui| {
                    for line in [
                        "Add real terminal emulation coverage for ANSI/VT state, resize, scrollback, and copy/paste",
                        "Extend the GUI launcher from SSH-first sessions into non-SSH transport windows",
                        "Promote ad-hoc quick-connect drafts from planning previews into live transport launches",
                    ] {
                        ui.label(format!("• {line}"));
                    }
                });

                section_card(ui, "Workspace references", |ui| {
                    ui.label(format!(
                        "Config path: {}",
                        self.model.options().config_path.display()
                    ));
                    ui.label(format!(
                        "Known-hosts path: {}",
                        self.model.options().known_hosts_path.display()
                    ));
                    ui.label("Manual: docs/tools/rustty.adoc");
                    ui.label("Suite changelog: CHANGELOG.adoc");
                    ui.label("Draft release notes: docs/release-notes/next.adoc");
                });
            });
    }

    fn render_diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Diagnostics").strong());
        ui.add_space(6.0);
        for line in self.model.diagnostics_lines() {
            ui.monospace(line);
        }
        if let Some(error) = self.model.config_error() {
            ui.add_space(8.0);
            ui.colored_label(Color32::from_rgb(154, 56, 48), error);
        }
    }

    fn render_terminal_window(&mut self, ctx: &Context) {
        let Some(snapshot) = self.model.terminal_window_snapshot() else {
            return;
        };
        if !snapshot.visible {
            return;
        }

        let title = format!("{} Terminal - {}", PRODUCT_NAME, snapshot.session_name);
        let mut open = true;
        egui::Window::new(title)
            .id(egui::Id::new("rustty-terminal-window"))
            .default_size([920.0, 700.0])
            .min_width(720.0)
            .min_height(520.0)
            .open(&mut open)
            .show(ctx, |ui| {
                self.render_terminal_window_contents(ui, &snapshot);
            });

        if !open {
            self.model.close_terminal_window();
        }
    }

    fn render_terminal_window_contents(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &TerminalWindowSnapshot,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(&snapshot.session_name);
            protocol_badge(ui, snapshot.protocol);
            ui.label(RichText::new(&snapshot.endpoint).color(Color32::from_rgb(99, 73, 60)));
            ui.label(
                RichText::new(window_activity_label(snapshot))
                    .color(Color32::from_rgb(108, 79, 64)),
            );
        });

        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "This dedicated session window now hosts both saved-session command runs and the first live SSH shell workflow, while RusTTY grows toward fuller terminal emulation.",
            )
            .color(Color32::from_rgb(102, 77, 64)),
        );

        ui.add_space(10.0);
        section_card(ui, "Session launch preview", |ui| {
            code_block(ui, &snapshot.launch_preview);
        });

        ui.add_space(10.0);
        section_card(ui, "Remote command", |ui| {
            if snapshot.protocol != Protocol::Ssh {
                ui.label(
                    RichText::new(
                        "Interactive GUI transport for this protocol is not implemented yet. The first dedicated terminal window currently targets saved SSH sessions.",
                    )
                    .italics()
                    .color(Color32::from_rgb(118, 92, 78)),
                );
                return;
            }

            let shell_busy = matches!(
                snapshot.shell_state,
                InteractiveShellState::ProbingHostKey(_)
                    | InteractiveShellState::AwaitingHostKeyConfirmation(_)
                    | InteractiveShellState::Connecting(_)
                    | InteractiveShellState::Running(_)
            );
            let command_busy = matches!(
                snapshot.command_runner_state,
                CommandRunnerState::ProbingHostKey(_)
                    | CommandRunnerState::AwaitingHostKeyConfirmation(_)
                    | CommandRunnerState::Running(_)
            );

            Grid::new("rustty-terminal-command-grid")
                .num_columns(2)
                .spacing(Vec2::new(16.0, 8.0))
                .show(ui, |ui| {
                    ui.label("Remote command");
                    if let Some(command_input) = self.model.terminal_window_command_mut() {
                        ui.text_edit_singleline(command_input);
                    } else {
                        ui.label("Terminal window is not available.");
                    }
                    ui.end_row();
                });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !shell_busy && !command_busy,
                        egui::Button::new("Start interactive shell"),
                    )
                    .clicked()
                {
                    let terminal_size =
                        estimate_terminal_size(Vec2::new(ui.available_width().max(720.0), 360.0));
                    if let Err(error) = self
                        .model
                        .start_terminal_window_interactive_shell(terminal_size)
                    {
                        self.model.set_status_message(error);
                    }
                }
                if ui
                    .add_enabled(
                        matches!(
                            snapshot.shell_state,
                            InteractiveShellState::Connecting(_)
                                | InteractiveShellState::Running(_)
                        ),
                        egui::Button::new("Disconnect shell"),
                    )
                    .clicked()
                {
                    if let Err(error) = self.model.shutdown_terminal_window_shell() {
                        self.model.set_status_message(error);
                    }
                }
                if ui
                    .add_enabled(
                        !shell_busy && !command_busy,
                        egui::Button::new("Run command"),
                    )
                    .clicked()
                {
                    if let Err(error) = self.model.start_terminal_window_command_run() {
                        self.model.set_status_message(error);
                    }
                }
                if ui.button("Copy command preview").clicked() {
                    copy_text(
                        ui.ctx(),
                        snapshot.command_preview.clone(),
                        &mut self.model,
                        format!(
                            "Copied terminal command preview for '{}'",
                            snapshot.session_name
                        ),
                    );
                }
                if (matches!(
                    snapshot.command_runner_state,
                    CommandRunnerState::Finished(_) | CommandRunnerState::Failed(_)
                ) || matches!(
                    snapshot.shell_state,
                    InteractiveShellState::Finished(_) | InteractiveShellState::Failed(_)
                )) && ui.button("Clear status").clicked()
                {
                    self.model.clear_command_runner_state();
                }
            });

            ui.add_space(8.0);
            code_block(ui, &snapshot.command_preview);

            match &snapshot.command_runner_state {
                CommandRunnerState::Idle => {}
                CommandRunnerState::ProbingHostKey(progress) => {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Probing the SSH host key for '{}' at {}:{}.",
                            progress.session_name, progress.host, progress.port
                        ));
                    });
                }
                CommandRunnerState::AwaitingHostKeyConfirmation(_) => {}
                CommandRunnerState::Running(progress) => {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Running '{}' on {}:{} for session '{}'.",
                            progress.command, progress.host, progress.port, progress.session_name
                        ));
                    });
                }
                CommandRunnerState::Finished(report) => {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "Completed with exit status {}. Host key: {} ({})",
                            report.exit_status, report.host_key_fingerprint, report.host_key_source
                        ))
                        .color(Color32::from_rgb(57, 108, 74)),
                    );
                    if report.persisted_host_key {
                        ui.label(
                            RichText::new(
                                "The accepted host key was appended to the RusTTY known-hosts file.",
                            )
                            .color(Color32::from_rgb(57, 108, 74)),
                        );
                    }
                    if let Some(warning) = &report.warning {
                        ui.colored_label(Color32::from_rgb(168, 97, 54), warning);
                    }
                }
                CommandRunnerState::Failed(error) => {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(154, 56, 48), error);
                }
            }

            match &snapshot.shell_state {
                InteractiveShellState::Idle => {}
                InteractiveShellState::ProbingHostKey(progress) => {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Probing the SSH host key for the interactive shell '{}' at {}:{}.",
                            progress.session_name, progress.host, progress.port
                        ));
                    });
                }
                InteractiveShellState::AwaitingHostKeyConfirmation(_) => {}
                InteractiveShellState::Connecting(progress) => {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Opening a PTY-backed shell on {}:{} for session '{}'.",
                            progress.host, progress.port, progress.session_name
                        ));
                    });
                }
                InteractiveShellState::Running(progress) => {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "Interactive shell is live on {}:{} for '{}'. Click the terminal surface below to focus input.",
                            progress.host, progress.port, progress.session_name
                        ))
                        .color(Color32::from_rgb(57, 108, 74)),
                    );
                }
                InteractiveShellState::Finished(report) => {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "Interactive shell exited with status {}. Host key: {} ({})",
                            report.exit_status, report.host_key_fingerprint, report.host_key_source
                        ))
                        .color(Color32::from_rgb(57, 108, 74)),
                    );
                    if report.persisted_host_key {
                        ui.label(
                            RichText::new(
                                "The accepted host key was appended to the RusTTY known-hosts file.",
                            )
                            .color(Color32::from_rgb(57, 108, 74)),
                        );
                    }
                }
                InteractiveShellState::Failed(error) => {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(154, 56, 48), error);
                }
            }

            if let Some(prompt) = pending_host_key_prompt(snapshot) {
                ui.add_space(8.0);
                self.render_terminal_host_key_prompt(ui, prompt);
            }
        });

        ui.add_space(10.0);
        section_card(ui, "Interactive shell", |ui| {
            if snapshot.protocol != Protocol::Ssh {
                ui.label(
                    RichText::new(
                        "The live terminal surface will appear here once GUI transport support exists for this protocol.",
                    )
                    .italics()
                    .color(Color32::from_rgb(118, 92, 78)),
                );
                return;
            }

            let shell_is_live = matches!(
                snapshot.shell_state,
                InteractiveShellState::Connecting(_) | InteractiveShellState::Running(_)
            );
            let response = terminal_surface(
                ui,
                if snapshot.shell_screen.is_empty() {
                    "Interactive shell output will appear here."
                } else {
                    &snapshot.shell_screen
                },
            );
            if response.clicked() {
                response.request_focus();
            }

            let terminal_size = estimate_terminal_size(response.rect.size());
            if let Err(error) = self.model.resize_terminal_window_shell(terminal_size) {
                self.model.set_status_message(error);
            }

            if shell_is_live && response.has_focus() {
                if let Err(error) = self.forward_terminal_input(ui.ctx()) {
                    self.model.set_status_message(error);
                }
            }

            ui.add_space(8.0);
            ui.label(
                RichText::new(if shell_is_live && response.has_focus() {
                    "Terminal input is focused. Typed keys and common control keys go to the remote PTY."
                } else if shell_is_live {
                    "Click the terminal surface to focus shell input."
                } else {
                    "Start an interactive shell to turn this surface into a live SSH terminal."
                })
                .italics()
                .color(Color32::from_rgb(112, 85, 70)),
            );
        });

        ui.add_space(10.0);
        section_card(ui, "Transcript", |ui| {
            transcript_surface(ui, &snapshot.transcript);
        });
    }

    fn render_terminal_host_key_prompt(
        &mut self,
        ui: &mut egui::Ui,
        prompt: &crate::model::HostKeyPrompt,
    ) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(247, 235, 224))
            .stroke(Stroke::new(1.0, Color32::from_rgb(209, 163, 126)))
            .inner_margin(Margin::same(10))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Unknown SSH host key")
                        .strong()
                        .color(Color32::from_rgb(141, 80, 44)),
                );
                ui.label(format!(
                    "Session '{}' reached {}:{} and needs confirmation before credentials are sent.",
                    prompt.session_name, prompt.host, prompt.port
                ));
                ui.label(format!("SHA-256 fingerprint: {}", prompt.fingerprint));
                ui.label(format!(
                    "Known-hosts path: {}",
                    prompt.known_hosts_path.display()
                ));
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Trust once").clicked() {
                        if let Err(error) = self.model.trust_pending_host_key_once() {
                            self.model.set_status_message(error);
                        }
                    }
                    if ui.button("Trust and save").clicked() {
                        if let Err(error) = self.model.trust_pending_host_key_and_save() {
                            self.model.set_status_message(error);
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.model.cancel_pending_host_key();
                    }
                });
            });
    }

    fn forward_terminal_input(&mut self, ctx: &Context) -> Result<(), String> {
        let mut bytes = Vec::new();
        for event in ctx.input(|input| input.events.clone()) {
            match event {
                egui::Event::Text(text) => bytes.extend_from_slice(text.as_bytes()),
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    if let Some(mapped) = map_terminal_key(key, modifiers) {
                        bytes.extend_from_slice(&mapped);
                    }
                }
                _ => {}
            }
        }

        if bytes.is_empty() {
            return Ok(());
        }

        self.model.send_terminal_window_shell_input(bytes)
    }
}

impl App for RusttyApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.model.poll_command_runner();
        if self.model.has_active_command_task() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        TopBottomPanel::top("rustty-top-bar")
            .frame(
                Frame::NONE
                    .fill(Color32::from_rgb(248, 242, 233))
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| self.render_top_bar(ui));

        TopBottomPanel::bottom("rustty-diagnostics")
            .resizable(true)
            .default_height(140.0)
            .frame(
                Frame::NONE
                    .fill(Color32::from_rgb(239, 231, 220))
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| self.render_diagnostics(ui));

        egui::SidePanel::left("rustty-sidebar")
            .default_width(290.0)
            .min_width(240.0)
            .resizable(true)
            .frame(
                Frame::NONE
                    .fill(Color32::from_rgb(244, 237, 228))
                    .inner_margin(Margin::same(12)),
            )
            .show(ctx, |ui| self.render_sidebar(ui));

        egui::CentralPanel::default()
            .frame(
                Frame::NONE
                    .fill(Color32::from_rgb(250, 246, 240))
                    .inner_margin(Margin::same(14)),
            )
            .show(ctx, |ui| match self.model.view() {
                LauncherView::Sessions => self.render_sessions_view(ui),
                LauncherView::Tools => self.render_tools_view(ui),
                LauncherView::About => self.render_about_view(ui),
            });

        self.render_terminal_window(ctx);
    }
}

fn configure_visuals(context: &Context) {
    let mut style = (*context.style()).clone();
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = Color32::from_rgb(250, 246, 240);
    style.visuals.extreme_bg_color = Color32::from_rgb(233, 226, 216);
    style.visuals.faint_bg_color = Color32::from_rgb(240, 232, 222);
    style.visuals.code_bg_color = Color32::from_rgb(236, 228, 218);
    style.visuals.selection.bg_fill = Color32::from_rgb(189, 108, 74);
    style.visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(189, 108, 74);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(221, 200, 181);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(241, 233, 224);
    style.visuals.window_fill = Color32::from_rgb(250, 246, 240);
    context.set_style(style);
}

fn copy_text(
    context: &Context,
    text: String,
    model: &mut LauncherModel,
    status_message: impl Into<String>,
) {
    context.copy_text(text);
    model.set_status_message(status_message);
}

fn render_session_editor_form(ui: &mut egui::Ui, draft: &mut SessionEditorDraft) -> String {
    ui.add_space(8.0);
    ui.horizontal_wrapped(|ui| {
        ui.label("Protocol");
        ComboBox::from_id_salt("rustty-session-editor-protocol")
            .selected_text(draft.protocol.label())
            .show_ui(ui, |ui| {
                for protocol in [
                    Protocol::Ssh,
                    Protocol::Scp,
                    Protocol::Sftp,
                    Protocol::Telnet,
                    Protocol::Raw,
                    Protocol::Rlogin,
                    Protocol::Serial,
                ] {
                    ui.selectable_value(&mut draft.protocol, protocol, protocol.label());
                }
            });

        ui.add_space(16.0);
        ui.label("Host-key policy");
        ComboBox::from_id_salt("rustty-session-editor-host-key-policy")
            .selected_text(host_key_policy_label(draft.host_key_policy))
            .show_ui(ui, |ui| {
                for policy in [
                    rustty_core::HostKeyPolicy::Ask,
                    rustty_core::HostKeyPolicy::Strict,
                    rustty_core::HostKeyPolicy::AcceptNew,
                ] {
                    ui.selectable_value(
                        &mut draft.host_key_policy,
                        policy,
                        host_key_policy_label(policy),
                    );
                }
            });
    });

    ui.add_space(8.0);
    Grid::new("rustty-session-editor-grid")
        .num_columns(2)
        .spacing(Vec2::new(16.0, 8.0))
        .show(ui, |ui| {
            ui.label("Session name");
            ui.text_edit_singleline(&mut draft.name);
            ui.end_row();

            ui.label("Host / endpoint");
            ui.text_edit_singleline(&mut draft.host);
            ui.end_row();

            ui.label("Port");
            ui.text_edit_singleline(&mut draft.port);
            ui.end_row();

            ui.label("Username");
            ui.text_edit_singleline(&mut draft.username);
            ui.end_row();

            ui.label("Password env");
            ui.text_edit_singleline(&mut draft.password_env);
            ui.end_row();

            ui.label("Private key path");
            ui.text_edit_singleline(&mut draft.private_key_path);
            ui.end_row();

            ui.label("Key passphrase env");
            ui.text_edit_singleline(&mut draft.key_passphrase_env);
            ui.end_row();

            ui.label("Keyboard-interactive env");
            ui.text_edit_singleline(&mut draft.keyboard_interactive_env);
            ui.end_row();
        });

    ui.add_space(10.0);
    ui.label(RichText::new("Forwarding").strong());
    ui.label(
        RichText::new(
            "Use one rule per line as `source -> target`. Dynamic forwards expect one listen address per line.",
        )
        .color(Color32::from_rgb(108, 79, 64)),
    );

    ui.add_space(8.0);
    ui.columns(3, |columns| {
        columns[0].label(RichText::new("Local forwards").strong());
        columns[0].add(egui::TextEdit::multiline(&mut draft.local_forwards).desired_rows(4));

        columns[1].label(RichText::new("Remote forwards").strong());
        columns[1].add(egui::TextEdit::multiline(&mut draft.remote_forwards).desired_rows(4));

        columns[2].label(RichText::new("Dynamic forwards").strong());
        columns[2].add(egui::TextEdit::multiline(&mut draft.dynamic_forwards).desired_rows(4));
    });

    ui.add_space(10.0);
    ui.label(RichText::new("Notes").strong());
    ui.add(egui::TextEdit::multiline(&mut draft.notes).desired_rows(3));

    draft.preview()
}

fn protocol_badge(ui: &mut egui::Ui, protocol: Protocol) {
    let color = protocol_color(protocol);
    Frame::group(ui.style())
        .fill(color.linear_multiply(0.10))
        .stroke(Stroke::new(1.0, color.linear_multiply(0.55)))
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(protocol.label()).strong().color(color));
        });
}

fn protocol_color(protocol: Protocol) -> Color32 {
    match protocol {
        Protocol::Ssh => Color32::from_rgb(33, 115, 88),
        Protocol::Scp => Color32::from_rgb(56, 98, 164),
        Protocol::Sftp => Color32::from_rgb(65, 128, 164),
        Protocol::Telnet => Color32::from_rgb(165, 92, 48),
        Protocol::Raw => Color32::from_rgb(118, 88, 153),
        Protocol::Rlogin => Color32::from_rgb(153, 72, 98),
        Protocol::Serial => Color32::from_rgb(128, 112, 53),
        Protocol::Agent => Color32::from_rgb(92, 112, 138),
        Protocol::Keygen => Color32::from_rgb(121, 93, 54),
    }
}

fn stats_card(ui: &mut egui::Ui, model: &LauncherModel) {
    Frame::group(ui.style())
        .fill(Color32::from_rgb(237, 228, 216))
        .stroke(Stroke::new(1.0, Color32::from_rgb(211, 197, 182)))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.label(RichText::new("Saved sessions").strong());
            ui.label(model.session_count().to_string());
            ui.add_space(6.0);
            ui.label(RichText::new("Imported").strong());
            ui.label(model.imported_session_count().to_string());
            ui.add_space(6.0);
            ui.label(RichText::new("SSH").strong());
            ui.label(model.protocol_count(Protocol::Ssh).to_string());
        });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).strong());
    ui.label(value);
    ui.end_row();
}

fn code_block(ui: &mut egui::Ui, value: &str) {
    Frame::group(ui.style())
        .fill(Color32::from_rgb(236, 228, 218))
        .stroke(Stroke::new(1.0, Color32::from_rgb(214, 198, 181)))
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.monospace(value);
        });
}

fn empty_state_card(ui: &mut egui::Ui, title: &str, body: &str) {
    section_card(ui, title, |ui| {
        ui.label(body);
    });
}

fn section_card(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    Frame::group(ui.style())
        .fill(Color32::from_rgb(244, 237, 228))
        .stroke(Stroke::new(1.0, Color32::from_rgb(214, 198, 181)))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).size(18.0).strong());
            ui.add_space(8.0);
            add_contents(ui);
        });
}

fn session_endpoint(stored_session: &StoredSession) -> String {
    let session = &stored_session.session;
    match (session.host.as_deref(), session.effective_port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => "No host configured".to_owned(),
    }
}

fn terminal_state_label(command_runner_state: &CommandRunnerState) -> &'static str {
    match command_runner_state {
        CommandRunnerState::Idle => "Ready",
        CommandRunnerState::ProbingHostKey(_) => "Probing host key",
        CommandRunnerState::AwaitingHostKeyConfirmation(_) => "Waiting for host-key confirmation",
        CommandRunnerState::Running(_) => "Running command",
        CommandRunnerState::Finished(_) => "Last command finished",
        CommandRunnerState::Failed(_) => "Last command failed",
    }
}

fn shell_state_label(shell_state: &InteractiveShellState) -> &'static str {
    match shell_state {
        InteractiveShellState::Idle => "Shell ready",
        InteractiveShellState::ProbingHostKey(_) => "Probing shell host key",
        InteractiveShellState::AwaitingHostKeyConfirmation(_) => {
            "Waiting for shell host-key confirmation"
        }
        InteractiveShellState::Connecting(_) => "Connecting interactive shell",
        InteractiveShellState::Running(_) => "Interactive shell live",
        InteractiveShellState::Finished(_) => "Last interactive shell finished",
        InteractiveShellState::Failed(_) => "Last interactive shell failed",
    }
}

fn window_activity_label(snapshot: &TerminalWindowSnapshot) -> &'static str {
    if !matches!(snapshot.shell_state, InteractiveShellState::Idle) {
        shell_state_label(&snapshot.shell_state)
    } else {
        terminal_state_label(&snapshot.command_runner_state)
    }
}

fn pending_host_key_prompt(
    snapshot: &TerminalWindowSnapshot,
) -> Option<&crate::model::HostKeyPrompt> {
    match &snapshot.shell_state {
        InteractiveShellState::AwaitingHostKeyConfirmation(prompt) => Some(prompt),
        InteractiveShellState::Idle
        | InteractiveShellState::ProbingHostKey(_)
        | InteractiveShellState::Connecting(_)
        | InteractiveShellState::Running(_)
        | InteractiveShellState::Finished(_)
        | InteractiveShellState::Failed(_) => match &snapshot.command_runner_state {
            CommandRunnerState::AwaitingHostKeyConfirmation(prompt) => Some(prompt),
            CommandRunnerState::Idle
            | CommandRunnerState::ProbingHostKey(_)
            | CommandRunnerState::Running(_)
            | CommandRunnerState::Finished(_)
            | CommandRunnerState::Failed(_) => None,
        },
    }
}

fn terminal_surface(ui: &mut egui::Ui, screen: &str) -> egui::Response {
    Frame::group(ui.style())
        .fill(Color32::from_rgb(26, 29, 33))
        .stroke(Stroke::new(1.0, Color32::from_rgb(63, 72, 82)))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.scope(|ui| {
                ui.visuals_mut().override_text_color = Some(Color32::from_rgb(230, 235, 240));
                ScrollArea::vertical()
                    .id_salt("rustty-terminal-screen")
                    .stick_to_bottom(true)
                    .max_height(360.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new(screen).monospace());
                    });
            });
        })
        .response
}

fn transcript_surface(ui: &mut egui::Ui, transcript: &[TerminalTranscriptEntry]) {
    Frame::group(ui.style())
        .fill(Color32::from_rgb(26, 29, 33))
        .stroke(Stroke::new(1.0, Color32::from_rgb(63, 72, 82)))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.scope(|ui| {
                ui.visuals_mut().override_text_color = Some(Color32::from_rgb(230, 235, 240));
                ScrollArea::vertical()
                    .id_salt("rustty-terminal-transcript")
                    .stick_to_bottom(true)
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for entry in transcript {
                            ui.label(
                                RichText::new(&entry.title)
                                    .monospace()
                                    .strong()
                                    .color(terminal_entry_title_color(entry.tone)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(&entry.body)
                                    .monospace()
                                    .color(terminal_entry_body_color(entry.tone)),
                            );
                            ui.add_space(10.0);
                        }
                    });
            });
        });
}

fn terminal_entry_title_color(tone: TerminalTranscriptTone) -> Color32 {
    match tone {
        TerminalTranscriptTone::Prompt => Color32::from_rgb(133, 224, 164),
        TerminalTranscriptTone::Info => Color32::from_rgb(156, 202, 255),
        TerminalTranscriptTone::Success => Color32::from_rgb(146, 228, 174),
        TerminalTranscriptTone::Warning => Color32::from_rgb(255, 205, 122),
        TerminalTranscriptTone::Error => Color32::from_rgb(255, 151, 139),
        TerminalTranscriptTone::Stdout => Color32::from_rgb(214, 223, 233),
        TerminalTranscriptTone::Stderr => Color32::from_rgb(255, 181, 149),
    }
}

fn terminal_entry_body_color(tone: TerminalTranscriptTone) -> Color32 {
    match tone {
        TerminalTranscriptTone::Prompt => Color32::from_rgb(226, 235, 240),
        TerminalTranscriptTone::Info => Color32::from_rgb(206, 219, 231),
        TerminalTranscriptTone::Success => Color32::from_rgb(212, 239, 221),
        TerminalTranscriptTone::Warning => Color32::from_rgb(245, 226, 195),
        TerminalTranscriptTone::Error => Color32::from_rgb(244, 212, 207),
        TerminalTranscriptTone::Stdout => Color32::from_rgb(224, 229, 235),
        TerminalTranscriptTone::Stderr => Color32::from_rgb(249, 215, 200),
    }
}

fn estimate_terminal_size(size: Vec2) -> TerminalSize {
    let pixel_width = size.x.max(320.0) as u32;
    let pixel_height = size.y.max(180.0) as u32;
    let columns = (size.x.max(320.0) / 8.0).floor().max(40.0) as u32;
    let rows = (size.y.max(180.0) / 18.0).floor().max(10.0) as u32;
    TerminalSize {
        columns,
        rows,
        pixel_width,
        pixel_height,
    }
}

fn map_terminal_key(key: egui::Key, modifiers: egui::Modifiers) -> Option<Vec<u8>> {
    if modifiers.ctrl {
        let control_byte = match key {
            egui::Key::A => Some(0x01),
            egui::Key::B => Some(0x02),
            egui::Key::C => Some(0x03),
            egui::Key::D => Some(0x04),
            egui::Key::E => Some(0x05),
            egui::Key::F => Some(0x06),
            egui::Key::K => Some(0x0b),
            egui::Key::L => Some(0x0c),
            egui::Key::N => Some(0x0e),
            egui::Key::P => Some(0x10),
            egui::Key::U => Some(0x15),
            egui::Key::W => Some(0x17),
            egui::Key::Z => Some(0x1a),
            _ => None,
        };
        if let Some(byte) = control_byte {
            return Some(vec![byte]);
        }
    }

    match key {
        egui::Key::Enter => Some(vec![b'\r']),
        egui::Key::Tab => Some(vec![b'\t']),
        egui::Key::Backspace => Some(vec![0x7f]),
        egui::Key::Escape => Some(vec![0x1b]),
        egui::Key::ArrowUp => Some(b"\x1b[A".to_vec()),
        egui::Key::ArrowDown => Some(b"\x1b[B".to_vec()),
        egui::Key::ArrowRight => Some(b"\x1b[C".to_vec()),
        egui::Key::ArrowLeft => Some(b"\x1b[D".to_vec()),
        egui::Key::Home => Some(b"\x1b[H".to_vec()),
        egui::Key::End => Some(b"\x1b[F".to_vec()),
        egui::Key::PageUp => Some(b"\x1b[5~".to_vec()),
        egui::Key::PageDown => Some(b"\x1b[6~".to_vec()),
        egui::Key::Delete => Some(b"\x1b[3~".to_vec()),
        _ => None,
    }
}
