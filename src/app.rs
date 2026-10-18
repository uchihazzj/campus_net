use std::sync::atomic::Ordering;
use std::time::Duration;

use egui::{RichText, ScrollArea};
use tray_icon::TrayIcon;

use crate::platform::autostart;
use crate::service::{config::StoredUser, AuthServerStatus, Ipv4InternetStatus, SharedState};
use crate::ui::l10n::{self, UiText};

mod edit_dialog;
mod icon;
mod presentation;
mod settings;
mod tray;
mod update_ui;
mod users;
pub(crate) mod window;

pub use icon::create_window_icon;
pub(crate) use presentation::configure_style;
use presentation::{
    card_frame, connection_status, current_campus_ipv4, tone_color, ConnectionStatus, Tone,
};
pub(crate) use tray::capture_main_hwnd;
pub(crate) use tray::install_window_restore_hook;
pub(crate) use tray::FORCE_QUIT;

pub struct CampusNetApp {
    state: SharedState,
    _tray_icon: Option<TrayIcon>,
    window_hidden: bool,
    pending_delete: Option<(usize, StoredUser)>,
    server_draft: String,
    server_original: String,
    editing_user_idx: Option<usize>,
    edit_username: String,
    edit_password: String,
    edit_ip: String,
    edit_if_name: String,
    edit_original_username: String,
    edit_original_ip: String,
    edit_original_if_name: String,
    show_add_dialog: bool,
    edit_error: bool,
    edit_detected_ip: Option<String>,
    edit_interfaces: Vec<(String, std::net::IpAddr)>,
    edit_network_rx: Option<crossbeam_channel::Receiver<Vec<(String, std::net::IpAddr)>>>,
}

impl CampusNetApp {
    pub fn new(state: SharedState) -> Self {
        let (lang, server) = {
            let s = state.lock().unwrap();
            (s.config.language, s.config.server.clone())
        };
        let t = l10n::get_text(lang);
        let tray_icon = tray::create_tray_icon(state.clone(), &t);

        let auto_start = state.lock().unwrap().config.auto_start;
        if auto_start {
            state.lock().unwrap().autostart_busy = true;
            let startup_state = state.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = autostart::enable_autostart() {
                    tracing::error!("Failed to enable autostart: {}", e);
                    startup_state
                        .lock()
                        .unwrap()
                        .add_log(format!("[ERROR] Failed to enable autostart: {}", e));
                }
                startup_state.lock().unwrap().autostart_busy = false;
                crate::service::request_ui_repaint();
            });
        }

        Self {
            state,
            _tray_icon: tray_icon,
            window_hidden: false,
            pending_delete: None,
            server_draft: server.clone(),
            server_original: server,
            editing_user_idx: None,
            edit_username: String::new(),
            edit_password: String::new(),
            edit_ip: String::new(),
            edit_if_name: String::new(),
            edit_original_username: String::new(),
            edit_original_ip: String::new(),
            edit_original_if_name: String::new(),
            show_add_dialog: false,
            edit_error: false,
            edit_detected_ip: None,
            edit_interfaces: Vec::new(),
            edit_network_rx: None,
        }
    }

    fn t(&self) -> UiText {
        let lang = {
            let s = self.state.lock().unwrap();
            s.config.language
        };
        l10n::get_text(lang)
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let (
            status,
            campus_ip,
            account,
            current_ip,
            server,
            auth_server,
            internet,
            query_busy,
            auth_busy,
            reconnect,
            fallback_offline,
        ) = {
            let s = self.state.lock().unwrap();
            (
                connection_status(&s),
                s.campus_ip.clone(),
                s.current_online_info().map(|info| info.user_name.clone()),
                current_campus_ipv4(&s),
                s.config.server.clone(),
                s.auth_server.clone(),
                s.ipv4_internet.clone(),
                s.online_query_busy,
                s.authentication_busy(),
                if !s.config.auto_reconnect {
                    t.reconnect_disabled
                } else if s.suppress_auto_reconnect {
                    t.reconnect_paused
                } else {
                    t.reconnect_enabled
                },
                s.definitely_offline() && s.online_info_fail_count > 0,
            )
        };
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !query_busy && !auth_busy,
                        egui::Button::new(t.btn_refresh_status),
                    )
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        crate::service::online_info::sync_online_state(&state).await;
                    });
                }
                if query_busy {
                    ui.spinner();
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.heading(RichText::new(t.window_title).size(22.0).strong());
                });
            });
        });
        card_frame(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (text, tone, hint) = match status {
                ConnectionStatus::Online => (
                    t.campus_auth_logged_in,
                    Tone::Positive,
                    t.campus_auth_confirmed,
                ),
                ConnectionStatus::LoggingIn => {
                    (t.status_logging_in, Tone::Warning, t.auth_busy_hint)
                }
                ConnectionStatus::LoggingOut => {
                    (t.status_logging_out, Tone::Warning, t.auth_busy_hint)
                }
                ConnectionStatus::Pending => {
                    (t.status_pending_confirm, Tone::Warning, t.pending_hint)
                }
                ConnectionStatus::Offline => (
                    t.campus_auth_not_logged_in,
                    Tone::Muted,
                    t.one_click_login_hint,
                ),
                ConnectionStatus::Stale => (
                    t.status_last_online,
                    Tone::Warning,
                    t.online_info_stale_hint,
                ),
                ConnectionStatus::Unknown => (t.campus_auth_unknown, Tone::Muted, t.unknown_hint),
            };
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    tone_color(ui, tone),
                    RichText::new(format!("●  {}", text)).size(18.0).strong(),
                )
                .on_hover_text(hint);
            });
            if let Some(account) = account {
                ui.add(
                    egui::Label::new(format!("{} {}", t.campus_account_label, account)).truncate(),
                )
                .on_hover_text(account);
            }
            ui.label(format!(
                "{} {}",
                t.campus_ip_label,
                current_ip
                    .map(|ip| ip.to_string())
                    .as_deref()
                    .unwrap_or(t.campus_ipv4_none)
            ));
            ui.small(reconnect);
            if matches!(
                status,
                ConnectionStatus::Pending | ConnectionStatus::Stale | ConnectionStatus::Unknown
            ) {
                ui.small(hint);
            }
        });
        egui::CollapsingHeader::new(t.section_details)
            .id_salt("connection_details")
            .show(ui, |ui| {
                ui.label(format!(
                    "{} {}",
                    t.campus_auth_label,
                    match status {
                        ConnectionStatus::Online => t.campus_auth_logged_in,
                        ConnectionStatus::Offline => t.campus_auth_not_logged_in,
                        _ => t.campus_auth_unknown,
                    }
                ));
                if fallback_offline {
                    ui.weak(t.offline_fallback_hint);
                }
                ui.label(format!(
                    "{} {}",
                    t.campus_ipv4_label,
                    campus_ip.as_deref().unwrap_or(t.campus_ipv4_none)
                ));
                let server_status = match auth_server {
                    AuthServerStatus::Reachable => t.auth_server_reachable,
                    AuthServerStatus::Unreachable => t.auth_server_unreachable,
                    AuthServerStatus::Unknown => t.auth_server_unknown,
                };
                ui.label(format!(
                    "{} {} · {}",
                    t.auth_server_label, server_status, server
                ));
                let internet_text = match internet {
                    Ipv4InternetStatus::Reachable => t.ipv4_internet_reachable,
                    Ipv4InternetStatus::CaptivePortal => t.ipv4_internet_captive,
                    Ipv4InternetStatus::Unreachable => t.ipv4_internet_unreachable,
                    Ipv4InternetStatus::ProbeFailed => t.ipv4_internet_probe_failed,
                    Ipv4InternetStatus::Checking => t.ipv4_internet_checking,
                    Ipv4InternetStatus::Disabled => t.ipv4_internet_disabled,
                };
                ui.label(format!("{} {}", t.ipv4_internet_label, internet_text));
                ui.weak(t.diagnostics_hint);
            });
    }

    fn render_log(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        crate::ui::log_panel::render_log_panel(&self.state, ui, &t);
    }

    fn save_config(&self) {
        crate::service::config::schedule_config_save(self.state.clone());
    }

    /// Shared by the native app and offline, in-memory UI verification.
    fn render_content(&mut self, ctx: &egui::Context) {
        let dialog_open = self.show_add_dialog
            || self.editing_user_idx.is_some()
            || self.pending_delete.is_some();
        egui::TopBottomPanel::bottom("version_footer")
            .frame(
                egui::Frame::side_top_panel(&ctx.style())
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0))
                    .fill(ctx.style().visuals.window_fill()),
            )
            .show(ctx, |ui| {
                ui.add_enabled_ui(!dialog_open, |ui| self.render_version_section(ui));
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(16.0))
            .show(ctx, |ui| {
                ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!dialog_open, |ui| {
                            self.render_top_bar(ui);
                            ui.add_space(8.0);
                            self.render_user_list(ui);
                            ui.add_space(8.0);
                            self.render_settings(ui);
                            self.render_log(ui);
                        });
                    });
            });
        self.render_edit_dialog(ctx);
        self.render_delete_dialog(ctx);
    }
}

impl eframe::App for CampusNetApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        tray::capture_main_hwnd(frame);
        crate::service::set_egui_ctx(ctx.clone());
        self.poll_edit_network_cache();

        let viewport = ctx.input(|i| i.viewport().clone());
        window::remember_normal_size(
            &mut self.state.lock().unwrap().config,
            &viewport,
            self.window_hidden,
        );

        if FORCE_QUIT.load(Ordering::SeqCst) {
            tracing::info!("[MainLoop] FORCE_QUIT — sending Close");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            self.save_config();
        }

        self.render_content(ctx);

        // Resolve tray requests after rendering so an in-flight close event
        // cannot append a hide command after a request to show the window.
        let hide_on_close =
            self.state.lock().unwrap().config.minimize_to_tray && self._tray_icon.is_some();
        let restore_size = {
            let s = self.state.lock().unwrap();
            window::startup_size(s.config.window_width, s.config.window_height)
        };
        match window::apply_visibility(
            ctx,
            tray::take_show_request(),
            hide_on_close,
            FORCE_QUIT.load(Ordering::SeqCst),
            restore_size,
        ) {
            window::WindowAction::Show => {
                self.window_hidden = false;
                tray::show_window(restore_size);
            }
            window::WindowAction::Hide => {
                self.window_hidden = true;
                self.state
                    .lock()
                    .unwrap()
                    .add_log("[INFO] Minimizing to tray (hiding window)".into());
            }
            window::WindowAction::None | window::WindowAction::Quit => {}
        }

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod preview_tests;
