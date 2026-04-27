use std::time::Duration;

use crossbeam_channel::Receiver;
use egui::{Color32, RichText, ScrollArea};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::core::srun::SrunClient;
use crate::core::utils::get_network_interfaces;
use crate::platform::autostart;
use crate::platform::secure_store;
use crate::service::auth;
use crate::service::config::{write_config, StoredUser};

use crate::service::{Ipv4InternetStatus, LoginState, SharedState};
use crate::ui::l10n::{self, Lang, UiText};

fn create_tray_icon_rgba() -> Icon {
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist < 13.0 && dist > 9.0 {
                rgba.extend_from_slice(&[66, 133, 244, 255]);
            } else if dist <= 9.0 && dist > 5.0 {
                rgba.extend_from_slice(&[100, 160, 255, 255]);
            } else if dist <= 5.0 {
                rgba.extend_from_slice(&[255, 255, 255, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, size, size).expect("Failed to create tray icon")
}

pub fn create_window_icon() -> egui::IconData {
    let size = 32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist < 13.0 && dist > 9.0 {
                rgba.extend_from_slice(&[66, 133, 244, 255]);
            } else if dist <= 9.0 && dist > 5.0 {
                rgba.extend_from_slice(&[100, 160, 255, 255]);
            } else if dist <= 5.0 {
                rgba.extend_from_slice(&[255, 255, 255, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}

pub struct CampusNetApp {
    state: SharedState,
    _tray_icon: TrayIcon,
    _show_id: MenuId,
    _login_all_id: MenuId,
    _logout_all_id: MenuId,
    _quit_id: MenuId,
    tray_rx: &'static Receiver<MenuEvent>,
    quit_requested: bool,
    // UI edit state
    editing_user_idx: Option<usize>,
    edit_username: String,
    edit_password: String,
    edit_ip: String,
    edit_if_name: String,
    edit_original_username: String,
    edit_original_ip: String,
    edit_original_if_name: String,
    show_add_dialog: bool,
    log_scroll_to_bottom: bool,
    // Reusable text cache
    cached_lang: Lang,
}

impl CampusNetApp {
    pub fn new(state: SharedState) -> Self {
        let lang = {
            let s = state.lock().unwrap();
            s.config.language
        };
        let t = l10n::get_text(lang);

        let tray_icon_rgba = create_tray_icon_rgba();

        let show_item = MenuItem::new(t.tray_show, true, None::<tray_icon::menu::accelerator::Accelerator>);
        let login_all_item = MenuItem::new(t.tray_login_all, true, None::<tray_icon::menu::accelerator::Accelerator>);
        let logout_all_item = MenuItem::new(t.tray_logout_all, true, None::<tray_icon::menu::accelerator::Accelerator>);
        let quit_item = MenuItem::new(t.tray_quit, true, None::<tray_icon::menu::accelerator::Accelerator>);

        let show_id = show_item.id().clone();
        let login_all_id = login_all_item.id().clone();
        let logout_all_id = logout_all_item.id().clone();
        let quit_id = quit_item.id().clone();

        let menu = Menu::new();
        menu.append(&show_item);
        menu.append(&login_all_item);
        menu.append(&logout_all_item);
        menu.append(&quit_item);

        let tray_rx = MenuEvent::receiver();

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(tray_icon_rgba)
            .with_tooltip(t.tray_tooltip)
            .build()
            .expect("Failed to create tray icon");

        {
            let s = state.lock().unwrap();
            if s.config.auto_start {
                let _ = autostart::enable_autostart();
            }
        }

        Self {
            state,
            _tray_icon: tray_icon,
            _show_id: show_id,
            _login_all_id: login_all_id,
            _logout_all_id: logout_all_id,
            _quit_id: quit_id,
            tray_rx,
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
            log_scroll_to_bottom: true,
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

    fn handle_tray_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.tray_rx.try_recv() {
            let id = event.id;
            if id == self._show_id {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            } else if id == self._login_all_id {
                let state = self.state.clone();
                tokio::spawn(async move { auth::do_login_all(state).await });
            } else if id == self._logout_all_id {
                let state = self.state.clone();
                tokio::spawn(async move { auth::do_logout_all(state).await });
            } else if id == self._quit_id {
                self.quit_requested = true;
                ctx.request_repaint();
            }
        }
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.horizontal(|ui| {
            ui.heading(RichText::new(t.window_title).size(20.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                let (campus_ip, ipv4_internet) = {
                    let s = self.state.lock().unwrap();
                    (
                        s.campus_ip.clone(),
                        s.ipv4_internet.clone(),
                    )
                };

                // Campus IPv4
                let ip_text = campus_ip.as_deref().unwrap_or(t.campus_ipv4_none);
                let ip_color = if campus_ip.is_some() { Color32::GREEN } else { Color32::GRAY };
                ui.colored_label(ip_color, format!("{} {}", t.campus_ipv4_label, ip_text));

                // IPv4 Internet
                let (inet_color, inet_text) = match ipv4_internet {
                    Ipv4InternetStatus::Reachable => (Color32::GREEN, t.ipv4_internet_reachable),
                    Ipv4InternetStatus::CaptivePortal => (Color32::YELLOW, t.ipv4_internet_captive),
                    Ipv4InternetStatus::Unreachable => (Color32::RED, t.ipv4_internet_unreachable),
                    Ipv4InternetStatus::ProbeFailed => (Color32::YELLOW, t.ipv4_internet_probe_failed),
                    Ipv4InternetStatus::Checking => (Color32::GRAY, t.ipv4_internet_checking),
                };
                ui.colored_label(inet_color, format!("{} {}", t.ipv4_internet_label, inet_text));
            });
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(t.server_label);
            let mut server = {
                let s = self.state.lock().unwrap();
                s.config.server.clone()
            };
            let resp = ui.add(
                egui::TextEdit::singleline(&mut server)
                    .hint_text(t.server_hint),
            ).on_hover_text(t.server_tooltip);
            if resp.changed() {
                let normalized = SrunClient::normalize_server_url(&server);
                let mut s = self.state.lock().unwrap();
                s.config.server = normalized;
            }
        });
    }

    fn render_user_card(&mut self, ui: &mut egui::Ui, user_idx: usize) {
        let t = self.t();
        let (username, state, current_ip, last_error) = {
            let s = self.state.lock().unwrap();
            if user_idx >= s.config.users.len() {
                return;
            }
            let user = &s.config.users[user_idx];
            let us = &s.user_statuses[user_idx];
            (
                user.username.clone(),
                us.state.clone(),
                us.current_ip.clone(),
                us.last_error.clone(),
            )
        };

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                match &state {
                    LoginState::Online => {
                        ui.colored_label(Color32::GREEN, "●");
                        ui.label(RichText::new(t.status_online).color(Color32::GREEN));
                    }
                    LoginState::LoggingIn => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_logging_in).color(Color32::YELLOW));
                    }
                    LoginState::LoggingOut => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_logging_out).color(Color32::YELLOW));
                    }
                    LoginState::LoggedOut => {
                        ui.colored_label(Color32::GRAY, "○");
                        ui.label(t.status_offline);
                    }
                    LoginState::Error => {
                        ui.colored_label(Color32::RED, "⬤");
                        ui.label(RichText::new(t.status_error).color(Color32::RED));
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Delete button
                    if ui
                        .button(t.btn_delete)
                        .on_hover_text(t.hint_delete)
                        .clicked()
                    {
                        {
                            let mut s = self.state.lock().unwrap();
                            s.config.users.remove(user_idx);
                            s.user_statuses.remove(user_idx);
                            s.add_log("[INFO] Removed user".to_string());
                        }
                        let _ = self.save_config();
                        return;
                    }

                    // Edit button
                    if ui.button(t.btn_edit).on_hover_text(t.hint_edit).clicked() {
                        let s = self.state.lock().unwrap();
                        if user_idx < s.config.users.len() {
                            let user = &s.config.users[user_idx];
                            self.editing_user_idx = Some(user_idx);
                            self.edit_username = user.username.clone();
                            self.edit_password.clear();
                            self.edit_ip = user.ip.clone().unwrap_or_default();
                            self.edit_if_name = user.if_name.clone().unwrap_or_default();
                            self.edit_original_username = user.username.clone();
                            self.edit_original_ip = user.ip.clone().unwrap_or_default();
                            self.edit_original_if_name = user.if_name.clone().unwrap_or_default();
                            self.show_add_dialog = false;
                        }
                    }

                    let is_busy =
                        state == LoginState::LoggingIn || state == LoginState::LoggingOut;

                    match &state {
                        LoginState::Online | LoginState::Error => {
                            if ui
                                .add_enabled(!is_busy, egui::Button::new(t.btn_logout))
                                .clicked()
                            {
                                let state = self.state.clone();
                                tokio::spawn(async move {
                                    auth::do_logout(state, user_idx).await;
                                });
                            }
                        }
                        _ => {
                            if ui
                                .add_enabled(!is_busy, egui::Button::new(t.btn_login))
                                .clicked()
                            {
                                let state = self.state.clone();
                                tokio::spawn(async move {
                                    auth::do_login(state, user_idx).await;
                                });
                            }
                        }
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.label(t.user_label);
                ui.label(RichText::new(&username).strong());
            });

            if !current_ip.is_empty() {
                ui.label(format!("{} {}", t.ip_label, current_ip));
            } else {
                let s = self.state.lock().unwrap();
                if let Some(user) = s.config.users.get(user_idx) {
                    if let Some(ref ip) = user.ip {
                        if !ip.is_empty() {
                            ui.label(format!("{} {}", t.ip_label, t.ip_configured.replace("{}", ip)));
                        } else if let Some(ref if_name) = user.if_name {
                            ui.label(t.ip_interface.replace("{}", if_name));
                        } else {
                            ui.label(t.ip_auto_detect);
                        }
                    } else if let Some(ref if_name) = user.if_name {
                        ui.label(t.ip_interface.replace("{}", if_name));
                    } else {
                        ui.label(t.ip_auto_detect);
                    }
                }
            }

            if let LoginState::Error = &state {
                if !last_error.is_empty() {
                    ui.colored_label(Color32::RED, format!("Error: {}", last_error));
                }
            }
        });
    }

    fn render_user_list(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let user_count = {
            let s = self.state.lock().unwrap();
            s.config.users.len()
        };

        if user_count == 0 {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(t.no_users_hint);
                ui.add_space(20.0);
            });
        } else {
            for idx in 0..user_count {
                self.render_user_card(ui, idx);
                ui.add_space(4.0);
            }
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button(t.btn_add_user).clicked() {
                self.editing_user_idx = None;
                self.edit_username.clear();
                self.edit_password.clear();
                self.edit_ip.clear();
                self.edit_if_name.clear();
                self.edit_original_username.clear();
                self.edit_original_ip.clear();
                self.edit_original_if_name.clear();
                // Auto-fill with 10.* IP if available, otherwise first private IP
                let ifaces = get_network_interfaces();
                let preferred = ifaces
                    .iter()
                    .find(|(_, ip)| ip.is_ipv4() && ip.to_string().starts_with("10."))
                    .or_else(|| ifaces.iter().find(|(_, ip)| ip.is_ipv4() && !ip.is_loopback()));
                if let Some((name, ip)) = preferred {
                    self.edit_ip = ip.to_string();
                    self.edit_if_name = name.clone();
                }
                self.show_add_dialog = true;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let any_busy = {
                    let s = self.state.lock().unwrap();
                    s.user_statuses
                        .iter()
                        .any(|us| us.state == LoginState::LoggingIn || us.state == LoginState::LoggingOut)
                };

                if ui.add_enabled(!any_busy, egui::Button::new(t.btn_login_all)).clicked() {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_login_all(state).await });
                }
                if ui.add_enabled(!any_busy, egui::Button::new(t.btn_logout_all)).clicked() {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_logout_all(state).await });
                }
            });
        });
    }

    fn render_edit_dialog(&mut self, ctx: &egui::Context) {
        let t = self.t();
        let show = self.show_add_dialog || self.editing_user_idx.is_some();
        if !show {
            return;
        }

        let is_new_user = self.show_add_dialog;
        let title = if is_new_user {
            t.edit_title_add
        } else {
            t.edit_title_edit
        };

        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(t.field_username);
                ui.text_edit_singleline(&mut self.edit_username);

                ui.label(t.field_password);
                let pwd_hint = if is_new_user { t.field_password_hint } else { t.field_password_hint_edit };
                ui.add(
                    egui::TextEdit::singleline(&mut self.edit_password)
                        .password(true)
                        .hint_text(pwd_hint),
                );

                ui.label(t.field_ip);
                ui.text_edit_singleline(&mut self.edit_ip)
                    .on_hover_text(t.field_ip_hint);

                ui.label(t.field_if_name);
                ui.text_edit_singleline(&mut self.edit_if_name)
                    .on_hover_text(t.field_if_name_hint);

                let interfaces = get_network_interfaces();
                if !interfaces.is_empty() {
                    ui.label(t.available_interfaces);
                    for (name, ip) in &interfaces {
                        if ui.button(format!("  {} — {}", name, ip)).clicked() {
                            self.edit_ip = ip.to_string();
                            self.edit_if_name.clone_from(name);
                        }
                    }
                } else {
                    ui.colored_label(Color32::YELLOW, "No network interfaces detected");
                }

                ui.add_space(8.0);

                // Determine if Save should be enabled
                let can_save = if is_new_user {
                    // New user: must have username and password
                    !self.edit_username.is_empty() && !self.edit_password.is_empty()
                } else {
                    // Editing existing: username required; password optional
                    // At least one field must have changed
                    !self.edit_username.is_empty()
                        && (self.edit_username != self.edit_original_username
                            || !self.edit_password.is_empty()
                            || self.edit_ip != self.edit_original_ip
                            || self.edit_if_name != self.edit_original_if_name)
                };

                ui.horizontal(|ui| {
                    if ui.button(t.btn_cancel).clicked() {
                        self.show_add_dialog = false;
                        self.editing_user_idx = None;
                    }

                    let save_btn = egui::Button::new(t.btn_save);
                    if ui.add_enabled(can_save, save_btn).clicked() {
                        let encrypted = if self.edit_password.is_empty() {
                            // Keep existing password when editing and password not changed
                            if let Some(idx) = self.editing_user_idx {
                                let s = self.state.lock().unwrap();
                                s.config.users[idx].encrypted_password.clone()
                            } else {
                                String::new()
                            }
                        } else {
                            secure_store::encrypt_password(&self.edit_password)
                                .unwrap_or_else(|_| String::new())
                        };

                        let new_user = StoredUser {
                            username: self.edit_username.clone(),
                            encrypted_password: encrypted,
                            ip: if self.edit_ip.is_empty() {
                                None
                            } else {
                                Some(self.edit_ip.clone())
                            },
                            if_name: if self.edit_if_name.is_empty() {
                                None
                            } else {
                                Some(self.edit_if_name.clone())
                            },
                        };

                        {
                            let mut s = self.state.lock().unwrap();
                            if let Some(idx) = self.editing_user_idx {
                                if idx < s.config.users.len() {
                                    s.config.users[idx] = new_user;
                                    let uname = s.config.users[idx].username.clone();
                                    s.add_log(format!("[INFO] Updated user {}", uname));
                                }
                            } else {
                                s.config.users.push(new_user);
                                s.user_statuses
                                    .push(crate::service::UserStatus::new());
                                let uname = s.config.users.last().unwrap().username.clone();
                                s.add_log(format!("[INFO] Added user {}", uname));
                            }
                            s.ensure_statuses();
                        }

                        let _ = self.save_config();
                        self.show_add_dialog = false;
                        self.editing_user_idx = None;
                    }
                });

                if !can_save {
                    ui.add_space(4.0);
                    if is_new_user {
                        ui.colored_label(Color32::GRAY, "Username and password are required");
                    } else if self.edit_username.is_empty() {
                        ui.colored_label(Color32::GRAY, "Username is required");
                    } else {
                        ui.colored_label(Color32::GRAY, "No changes detected");
                    }
                }
            });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.collapsing(t.section_settings, |ui| {
            let (mut auto_reconnect, mut minimize_to_tray, mut auto_start, mut detect_ip, mut strict_bind, mut double_stack, mut monitor_interval, mut retry_times, mut retry_delay, mut n, mut utype, mut acid, mut os, mut name) = {
                let s = self.state.lock().unwrap();
                let c = &s.config;
                (
                    c.auto_reconnect,
                    c.minimize_to_tray,
                    c.auto_start,
                    c.detect_ip,
                    c.strict_bind,
                    c.double_stack,
                    c.monitor_interval_secs,
                    c.retry_times,
                    c.retry_delay,
                    c.n,
                    c.utype,
                    c.acid,
                    c.os.clone(),
                    c.name.clone(),
                )
            };
            let mut lang = {
                let s = self.state.lock().unwrap();
                s.config.language
            };

            let mut changed = false;

            // Language selector
            ui.horizontal(|ui| {
                ui.label(t.label_language);
                if ui
                    .selectable_label(lang == Lang::English, Lang::English.as_str())
                    .clicked()
                {
                    lang = Lang::English;
                    changed = true;
                }
                if ui
                    .selectable_label(lang == Lang::Chinese, Lang::Chinese.as_str())
                    .clicked()
                {
                    lang = Lang::Chinese;
                    changed = true;
                }
            });
            ui.separator();

            ui.label(t.section_auth_params);
            ui.horizontal(|ui| {
                ui.label(t.label_n);
                changed |= ui.add(egui::DragValue::new(&mut n).range(1..=999)).changed();
                ui.label(t.label_type);
                changed |= ui.add(egui::DragValue::new(&mut utype).range(1..=99)).changed();
                ui.label(t.label_acid);
                changed |= ui.add(egui::DragValue::new(&mut acid).range(1..=999)).changed();
            });

            ui.horizontal(|ui| {
                ui.label(t.label_os);
                changed |= ui.text_edit_singleline(&mut os).changed();
                ui.label(t.label_name);
                changed |= ui.text_edit_singleline(&mut name).changed();
            });

            ui.separator();
            ui.label(t.section_network_options);
            changed |= ui.checkbox(&mut detect_ip, t.opt_detect_ip).changed();
            changed |= ui
                .checkbox(&mut strict_bind, t.opt_strict_bind)
                .on_hover_text(t.opt_strict_bind_hint)
                .changed();
            changed |= ui.checkbox(&mut double_stack, t.opt_double_stack).changed();

            ui.separator();
            ui.label(t.section_retry_options);
            ui.horizontal(|ui| {
                ui.label(t.label_retry_times);
                changed |= ui
                    .add(egui::DragValue::new(&mut retry_times).range(1..=99))
                    .changed();
                ui.label(t.label_retry_delay);
                changed |= ui
                    .add(egui::DragValue::new(&mut retry_delay).range(100..=30000))
                    .changed();
            });

            ui.separator();
            ui.label(t.section_app_options);
            changed |= ui.checkbox(&mut auto_reconnect, t.opt_auto_reconnect).changed();
            changed |= ui.checkbox(&mut minimize_to_tray, t.opt_minimize_tray).changed();

            let as_changed = ui.checkbox(&mut auto_start, t.opt_auto_start).changed();
            if as_changed {
                let result = if auto_start {
                    autostart::enable_autostart()
                } else {
                    autostart::disable_autostart()
                };
                if let Err(e) = result {
                    tracing::error!("Failed to change autostart: {}", e);
                    auto_start = !auto_start;
                }
                changed = true;
            }

            let old_interval = monitor_interval;
            ui.label(t.label_monitor_interval);
            let interval_changed = ui
                .add(
                    egui::DragValue::new(&mut monitor_interval)
                        .range(15..=300)
                        .suffix(format!(" {}", t.seconds_unit)),
                )
                .changed();
            if interval_changed && monitor_interval != old_interval {
                let mut s = self.state.lock().unwrap();
                s.add_log(format!(
                    "[INFO] Network check interval changed to {}s",
                    monitor_interval
                ));
            }
            changed |= interval_changed;

            if changed {
                {
                    let mut s = self.state.lock().unwrap();
                    s.config.language = lang;
                    s.config.auto_reconnect = auto_reconnect;
                    s.config.minimize_to_tray = minimize_to_tray;
                    s.config.auto_start = auto_start;
                    s.config.detect_ip = detect_ip;
                    s.config.strict_bind = strict_bind;
                    s.config.double_stack = double_stack;
                    s.config.monitor_interval_secs = monitor_interval;
                    s.config.retry_times = retry_times;
                    s.config.retry_delay = retry_delay;
                    s.config.n = n;
                    s.config.utype = utype;
                    s.config.acid = acid;
                    s.config.os = os;
                    s.config.name = name;
                }
                let _ = self.save_config();
            }
        });
    }

    fn render_log(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.collapsing(t.section_log, |ui| {
            let log_msgs: Vec<String> = {
                let s = self.state.lock().unwrap();
                s.log_messages.clone()
            };

            let mut text = log_msgs.join("\n");

            ScrollArea::vertical()
                .max_height(200.0)
                .auto_shrink([false; 2])
                .stick_to_bottom(self.log_scroll_to_bottom)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.log_scroll_to_bottom, t.opt_auto_scroll);
                if ui.button(t.btn_clear).clicked() {
                    let mut s = self.state.lock().unwrap();
                    s.log_messages.clear();
                }
            });
        });
    }

    fn save_config(&self) -> anyhow::Result<()> {
        let s = self.state.lock().unwrap();
        write_config("config.json", &s.config)
    }
}

impl eframe::App for CampusNetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_tray_events(ctx);

        if self.quit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            // Save current window size before closing
            if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
                let size = rect.size();
                let mut s = self.state.lock().unwrap();
                s.config.window_width = Some(size.x);
                s.config.window_height = Some(size.y);
                drop(s);
                let _ = self.save_config();
            }

            let minimize = {
                let s = self.state.lock().unwrap();
                s.config.minimize_to_tray
            };
            if minimize {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
        }

        self.render_edit_dialog(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                self.render_top_bar(ui);
                ui.add_space(8.0);
                self.render_user_list(ui);
                ui.add_space(8.0);
                self.render_settings(ui);
                ui.add_space(8.0);
                self.render_log(ui);
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.hyperlink_to(
                        "github.com/uchihazzj/campus_net",
                        "https://github.com/uchihazzj/campus_net",
                    );
                });
                ui.add_space(4.0);
            });
        });

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}
