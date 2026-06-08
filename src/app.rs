use std::sync::atomic::Ordering;
use std::time::Duration;

use egui::{Color32, RichText, ScrollArea};
use tray_icon::TrayIcon;

use crate::core::srun::SrunClient;
use crate::path::config_path;
use crate::platform::autostart;
use crate::service::config::write_config;
use crate::service::{Ipv4InternetStatus, SharedState};
use crate::ui::l10n::{self, Lang, UiText};

mod edit_dialog;
mod icon;
mod settings;
mod tray;
mod update_ui;
mod users;

pub use icon::create_window_icon;
pub(crate) use tray::FORCE_QUIT;

pub struct CampusNetApp {
    state: SharedState,
    _tray_icon: Option<TrayIcon>,
    quit_requested: bool,
    editing_user_idx: Option<usize>,
    edit_username: String,
    edit_password: String,
    edit_ip: String,
    edit_if_name: String,
    edit_original_username: String,
    edit_original_ip: String,
    edit_original_if_name: String,
    show_add_dialog: bool,
    edit_detected_ip: Option<String>,
    edit_interfaces: Vec<(String, std::net::IpAddr)>,
    cached_lang: Lang,
}

impl CampusNetApp {
    pub fn new(state: SharedState) -> Self {
        let lang = {
            let s = state.lock().unwrap();
            s.config.language
        };
        let t = l10n::get_text(lang);
        let tray_icon = tray::create_tray_icon(state.clone(), &t);

        {
            let s = state.lock().unwrap();
            if s.config.auto_start {
                let _ = autostart::enable_autostart();
            }
        }

        Self {
            state,
            _tray_icon: tray_icon,
            quit_requested: false,
            editing_user_idx: None,
            edit_username: String::new(),
            edit_password: String::new(),
            edit_ip: String::new(),
            edit_if_name: String::new(),
            edit_original_username: String::new(),
            edit_original_ip: String::new(),
            edit_original_if_name: String::new(),
            show_add_dialog: false,
            edit_detected_ip: None,
            edit_interfaces: Vec::new(),
            cached_lang: lang,
        }
    }

    fn t(&mut self) -> UiText {
        let lang = {
            let s = self.state.lock().unwrap();
            s.config.language
        };
        self.cached_lang = lang;
        l10n::get_text(lang)
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.horizontal(|ui| {
            ui.heading(RichText::new(t.window_title).size(20.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                let (campus_ip, ipv4_internet, online_info) = {
                    let s = self.state.lock().unwrap();
                    (
                        s.campus_ip.clone(),
                        s.ipv4_internet.clone(),
                        s.online_info.clone(),
                    )
                };

                if let Some(ref info) = online_info {
                    ui.colored_label(
                        Color32::GREEN,
                        format!("{} {}", t.campus_account_label, info.user_name),
                    );
                }

                let ip_text = campus_ip.as_deref().unwrap_or(t.campus_ipv4_none);
                let ip_color = if campus_ip.is_some() {
                    Color32::GREEN
                } else {
                    Color32::GRAY
                };
                ui.colored_label(ip_color, format!("{} {}", t.campus_ipv4_label, ip_text));

                if ipv4_internet != Ipv4InternetStatus::Disabled {
                    let (inet_color, inet_text) = match ipv4_internet {
                        Ipv4InternetStatus::Reachable => {
                            (Color32::GREEN, t.ipv4_internet_reachable)
                        }
                        Ipv4InternetStatus::CaptivePortal => {
                            (Color32::YELLOW, t.ipv4_internet_captive)
                        }
                        Ipv4InternetStatus::Unreachable => {
                            (Color32::RED, t.ipv4_internet_unreachable)
                        }
                        Ipv4InternetStatus::ProbeFailed => {
                            (Color32::YELLOW, t.ipv4_internet_probe_failed)
                        }
                        Ipv4InternetStatus::Checking => (Color32::GRAY, t.ipv4_internet_checking),
                        Ipv4InternetStatus::Disabled => (Color32::GRAY, ""),
                    };
                    ui.colored_label(
                        inet_color,
                        format!("{} {}", t.ipv4_internet_label, inet_text),
                    );
                }
            });
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(t.server_label);
            let mut server = {
                let s = self.state.lock().unwrap();
                s.config.server.clone()
            };
            let resp = ui
                .add(egui::TextEdit::singleline(&mut server).hint_text(t.server_hint))
                .on_hover_text(t.server_tooltip);
            if resp.changed() {
                let normalized = SrunClient::normalize_server_url(&server);
                let mut s = self.state.lock().unwrap();
                s.config.server = normalized;
            }
            if ui.button(t.btn_refresh_status).clicked() {
                let state = self.state.clone();
                tokio::spawn(async move {
                    crate::service::online_info::sync_online_state(&state).await;
                });
            }
        });
    }

    fn render_log(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        crate::ui::log_panel::render_log_panel(&self.state, ui, &t);
    }

    fn save_config(&self) {
        let config = {
            let s = self.state.lock().unwrap();
            s.config.clone()
        };
        let result = write_config(config_path(), &config);
        if let Err(ref e) = result {
            tracing::error!("Failed to save config: {}", e);
            if let Ok(mut s) = self.state.lock() {
                s.add_log(format!("[ERROR] Failed to save config: {}", e));
            }
        }
    }
}

impl eframe::App for CampusNetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        tray::capture_main_hwnd();
        crate::service::set_egui_ctx(ctx.clone());
        tray::sync_visible_after_native_show(ctx);

        if self.quit_requested || FORCE_QUIT.load(Ordering::SeqCst) {
            tracing::info!(
                "[MainLoop] quit_requested={}, FORCE_QUIT={} — sending Close",
                self.quit_requested,
                FORCE_QUIT.load(Ordering::SeqCst)
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
                let size = rect.size();
                let mut s = self.state.lock().unwrap();
                s.config.window_width = Some(size.x);
                s.config.window_height = Some(size.y);
                drop(s);
                self.save_config();
            }

            let force = FORCE_QUIT.load(Ordering::SeqCst);
            let minimize = if force {
                false
            } else {
                let s = self.state.lock().unwrap();
                s.config.minimize_to_tray
            };
            if minimize {
                tracing::info!("[MainLoop] Close requested → hiding to tray (Visible(false))");
                {
                    let mut s = self.state.lock().unwrap();
                    s.add_log("[INFO] Minimizing to tray (hiding window)".to_string());
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                tray::hide_window();
            } else {
                tracing::info!("[MainLoop] Close requested → real quit (minimize_to_tray=false)");
            }
        }

        self.render_edit_dialog(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                self.render_top_bar(ui);
                ui.add_space(8.0);
                self.render_user_list(ui);
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.hyperlink_to(
                        "github.com/uchihazzj/campus_net",
                        "https://github.com/uchihazzj/campus_net",
                    );
                });
                ui.add_space(4.0);
                self.render_version_section(ui);
                ui.add_space(8.0);
                self.render_settings(ui);
                ui.add_space(8.0);
                self.render_log(ui);
                ui.add_space(4.0);
            });
        });

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}
