//! Native egui application shell for the RusTTY launcher.

use eframe::{
    App, CreationContext, NativeOptions,
    egui::{
        self, Align, Color32, ComboBox, Context, Frame, Grid, Layout, Margin, RichText, ScrollArea,
        Stroke, TopBottomPanel, Vec2, ViewportBuilder,
    },
};
use rustty_config::StoredSession;
use rustty_core::{ALL_TOOLS, PRODUCT_NAME, Protocol};

use crate::model::{
    LauncherModel, LauncherOptions, LauncherView, host_key_policy_label, import_source_label,
    session_launch_preview, storage_format_label,
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
                        "Create a sample config from the toolbar to populate the launcher with a starter SSH session.",
                    );
                } else if let Some(error) = self.model.config_error() {
                    empty_state_card(
                        ui,
                        "Config needs attention",
                        &format!("The launcher opened, but config loading failed: {error}"),
                    );
                }

                if let Some(stored_session) = self.model.selected_session() {
                    self.render_selected_session(ui, &stored_session);
                } else if self.model.has_loaded_config() {
                    empty_state_card(
                        ui,
                        "No saved session selected",
                        "Use the left-hand list to inspect saved sessions, migration notes, and launch previews.",
                    );
                }

                ui.add_space(14.0);
                self.render_quick_connect(ui);
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
        });
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
                        "This draft is a launcher-side planning aid until the embedded terminal window lands.",
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
                        "This is the first real native RusTTY GUI client. It loads RusTTY config data, surfaces migrated PuTTY sessions, and gives operators a desktop place to review launch plans and diagnostics.",
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "The embedded terminal emulator and live GUI transport window are still the next milestone, so connection previews currently hand off to the CLI tools or explain what remains.",
                        )
                        .color(Color32::from_rgb(108, 79, 64)),
                    );
                });

                section_card(ui, "Current GUI scope", |ui| {
                    for line in [
                        "Native launcher window with session browser and quick-connect draft",
                        "Config-state diagnostics, sample-config creation, and path copy actions",
                        "Read-only inspection of saved auth defaults, forwarding, and import provenance",
                        "Tool catalog with manual and changelog path discovery",
                    ] {
                        ui.label(format!("• {line}"));
                    }
                });

                section_card(ui, "Next terminal milestones", |ui| {
                    for line in [
                        "Embed the interactive SSH session window into `rustty` instead of deferring to `rusplink`",
                        "Add real terminal emulation coverage for ANSI/VT state, resize, scrollback, and copy/paste",
                        "Extend the GUI launcher into session editing, saving, and live host-key prompts",
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
}

impl App for RusttyApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
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
