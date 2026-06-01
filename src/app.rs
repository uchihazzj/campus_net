use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use egui::{Color32, RichText, ScrollArea};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::core::srun::SrunClient;
use crate::core::utils::get_network_interfaces;
use crate::path::config_path;
use crate::platform::autostart;
use crate::platform::secure_store;
use crate::service::auth;
use crate::service::config::{write_config, StoredUser};

use crate::service::{Ipv4InternetStatus, LoginState, SharedState, UpdateStatus};
use crate::ui::l10n::{self, Lang, UiText};

// ── Windows native window handle ───────────────────────
static MAIN_HWND: OnceLock<isize> = OnceLock::new();
pub(crate) static FORCE_QUIT: AtomicBool = AtomicBool::new(false);
/// Set by native_show_window() — signals the next update() to sync
/// eframe's viewport visibility state via Visible(true). This is
/// needed because native ShowWindow bypasses eframe/winit state tracking.
static SYNC_VISIBLE: AtomicBool = AtomicBool::new(false);

fn capture_main_hwnd() {
    if MAIN_HWND.get().is_some() {
        return;
    }
    // Find the main window by title. winit/eframe uses this title.
    let title: Vec<u16> = "Campus Net Client\0".encode_utf16().collect();
    let hwnd = unsafe { FindWindowW(std::ptr::null_mut(), title.as_ptr()) };
    if hwnd != 0 {
        let _ = MAIN_HWND.set(hwnd);
        tracing::info!("[Native] Captured main window HWND={}", hwnd);
    }
}

fn native_show_window() {
    if let Some(&hwnd) = MAIN_HWND.get() {
        tracing::info!("[Native] ShowWindow: hwnd={}", hwnd);
        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
        // Signal the next update() to sync eframe visibility state
        SYNC_VISIBLE.store(true, Ordering::SeqCst);
    } else {
        tracing::warn!("[Native] ShowWindow failed: no HWND captured yet");
    }
}

fn native_force_quit(state: &SharedState) {
    tracing::info!("[Native] Force quit from tray");
    // Save config before exiting
    if let Ok(mut s) = state.lock() {
        if let Err(e) = write_config(config_path(), &s.config) {
            tracing::error!("Failed to save config on quit: {}", e);
        }
        s.add_log("[INFO] Quit from tray menu".to_string());
        tracing::info!("[Native] Config saved, initiating quit");
    }
    FORCE_QUIT.store(true, Ordering::SeqCst);
    if let Some(&hwnd) = MAIN_HWND.get() {
        tracing::info!("[Native] Posting WM_CLOSE to hwnd={}", hwnd);
        unsafe {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
    }
    // Fallback: if event loop doesn't respond, force exit after 2s
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        tracing::info!("[Native] Fallback: calling process::exit(0)");
        std::process::exit(0);
    });
}

// ── Windows FFI (no extra dependencies) ────────────────
#[cfg(target_os = "windows")]
extern "system" {
    fn FindWindowW(class: *const u16, title: *const u16) -> isize;
    fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
    fn SetForegroundWindow(hwnd: isize) -> i32;
    fn PostMessageW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> i32;
}

#[cfg(target_os = "windows")]
const SW_SHOW: i32 = 5;
#[cfg(target_os = "windows")]
const SW_RESTORE: i32 = 9;
#[cfg(target_os = "windows")]
const SW_HIDE: i32 = 0;
#[cfg(target_os = "windows")]
const WM_CLOSE: u32 = 0x0010;

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

fn should_show_logout_button(state: &LoginState) -> bool {
    matches!(state, LoginState::Online | LoginState::PendingConfirm)
}

pub struct CampusNetApp {
    state: SharedState,
    _tray_icon: TrayIcon,
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

        let show_item = MenuItem::new(
            t.tray_show,
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let login_all_item = MenuItem::new(
            t.tray_login_all,
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let logout_all_item = MenuItem::new(
            t.tray_logout_all,
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let quit_item = MenuItem::new(
            t.tray_quit,
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );

        let show_id = show_item.id().clone();
        let login_all_id = login_all_item.id().clone();
        let logout_all_id = logout_all_item.id().clone();
        let quit_id = quit_item.id().clone();

        tracing::info!(
            "Tray menu IDs — show={:?}, login_all={:?}, logout_all={:?}, quit={:?}",
            show_id,
            login_all_id,
            logout_all_id,
            quit_id
        );

        let menu = Menu::new();
        let _ = menu.append(&show_item);
        let _ = menu.append(&login_all_item);
        let _ = menu.append(&logout_all_item);
        let _ = menu.append(&quit_item);

        // ── Tray event listener thread ──────────────────
        // Uses blocking select! on both MenuEvent and TrayIconEvent channels.
        // ALL actions handled directly with native Windows API or tokio spawn —
        // no dependency on eframe update() loop for tray operations.
        let tokio_handle = tokio::runtime::Handle::current();
        let state_for_listener = state.clone();

        std::thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            let tray_rx = TrayIconEvent::receiver();
            tracing::info!(
                "[TrayListener] Thread started, listening for MenuEvent + TrayIconEvent..."
            );

            loop {
                crossbeam_channel::select! {
                    recv(menu_rx) -> result => {
                        match result {
                            Ok(event) => {
                                let id = event.id;
                                tracing::info!("[TrayListener] MenuEvent id={:?}", id);

                                if id == show_id {
                                    tracing::info!("[TrayListener] → ShowWindow");
                                    {
                                        let mut s = state_for_listener.lock().unwrap();
                                        s.add_log("[INFO] Tray menu: show window".to_string());
                                    }
                                    native_show_window();
                                } else if id == login_all_id {
                                    tracing::info!("[TrayListener] → OneClickLogin");
                                    // Set first user to LoggingIn immediately for UI feedback,
                                    // then spawn the task which handles the actual login.
                                    {
                                        let mut s = state_for_listener.lock().unwrap();
                                        s.add_log("[INFO] One-click login requested from tray".to_string());
                                        let count = s.config.users.len();
                                        if count > 0 {
                                            // Reset all non-Online users first
                                            for i in 0..count {
                                                if s.user_statuses[i].state != LoginState::Online {
                                                    s.user_statuses[i].state = LoginState::LoggedOut;
                                                    s.user_statuses[i].last_error.clear();
                                                }
                                            }
                                        }
                                    }
                                    crate::service::request_ui_repaint();
                                    let st = state_for_listener.clone();
                                    tokio_handle.spawn(async move {
                                        tracing::info!("[OneClickLogin] Task started from tray");
                                        auth::do_one_click_login(st).await;
                                        tracing::info!("[OneClickLogin] Task completed");
                                    });
                                } else if id == logout_all_id {
                                    tracing::info!("[TrayListener] → OneClickLogout");
                                    {
                                        let mut s = state_for_listener.lock().unwrap();
                                        s.add_log("[INFO] One-click logout requested from tray".to_string());
                                    }
                                    crate::service::request_ui_repaint();
                                    let st = state_for_listener.clone();
                                    tokio_handle.spawn(async move {
                                        tracing::info!("[OneClickLogout] Task started from tray");
                                        auth::do_one_click_logout(st).await;
                                        tracing::info!("[OneClickLogout] Task completed");
                                    });
                                } else if id == quit_id {
                                    tracing::info!("[TrayListener] → Quit");
                                    native_force_quit(&state_for_listener);
                                } else {
                                    tracing::warn!("[TrayListener] Unknown MenuEvent id={:?}", id);
                                }
                            }
                            Err(crossbeam_channel::RecvError) => {
                                tracing::info!("[TrayListener] MenuEvent channel disconnected");
                                break;
                            }
                        }
                    }
                    recv(tray_rx) -> result => {
                        match result {
                            Ok(event) => {
                                tracing::info!("[TrayListener] TrayIconEvent: {:?}", event);
                                match &event {
                                    TrayIconEvent::Click { button, button_state, .. }
                                        if matches!(button, tray_icon::MouseButton::Left)
                                           && matches!(button_state, tray_icon::MouseButtonState::Up) =>
                                    {
                                        tracing::info!("[TrayListener] Left-click → show window");
                                        {
                                            let mut s = state_for_listener.lock().unwrap();
                                            s.add_log("[INFO] Tray left-click: show window".to_string());
                                        }
                                        native_show_window();
                                    }
                                    TrayIconEvent::DoubleClick { button, .. } => {
                                        if matches!(button, tray_icon::MouseButton::Left) {
                                            tracing::info!("[TrayListener] Left double-click → show window");
                                            {
                                                let mut s = state_for_listener.lock().unwrap();
                                                s.add_log("[INFO] Tray double-click: show window".to_string());
                                            }
                                            native_show_window();
                                        }
                                    }
                                    _ => {
                                        // Enter/Move/Leave — no action needed
                                    }
                                }
                            }
                            Err(crossbeam_channel::RecvError) => {
                                tracing::info!("[TrayListener] TrayIconEvent channel disconnected");
                                break;
                            }
                        }
                    }
                }
            }
        });

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(tray_icon_rgba)
            .with_tooltip(t.tray_tooltip)
            .build()
            .expect("Failed to create tray icon");

        tracing::info!("Tray icon created successfully");

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

                // IPv4 internet status — only shown when probe is enabled
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
                        Ipv4InternetStatus::Disabled => {
                            // guarded by `!= Disabled` above; fallback
                            (Color32::GRAY, "")
                        }
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
            // Refresh status button — manually re-queries rad_user_info
            if ui.button(t.btn_refresh_status).clicked() {
                let state = self.state.clone();
                tokio::spawn(async move {
                    crate::service::online_info::sync_online_state(&state).await;
                });
            }
        });
    }

    fn render_user_card(&mut self, ui: &mut egui::Ui, user_idx: usize) {
        let t = self.t();
        let (username, state, current_ip, last_error) = {
            let s = self.state.lock().unwrap();
            let Some(user) = s.config.users.get(user_idx) else {
                return;
            };
            let Some(us) = s.user_statuses.get(user_idx) else {
                return;
            };
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
                        // Show "✓ Confirmed" when server confirms this user
                        let (confirmed, stale) = {
                            let s = self.state.lock().unwrap();
                            let c = s
                                .online_info
                                .as_ref()
                                .map(|info| {
                                    crate::service::online_info::match_account(
                                        &info.user_name,
                                        &s.config.users,
                                    )
                                })
                                .map(|mr| match mr {
                                    crate::service::online_info::MatchResult::Exact(i)
                                    | crate::service::online_info::MatchResult::UniqueBase(i) => {
                                        i == user_idx
                                    }
                                    _ => false,
                                })
                                .unwrap_or(false);
                            (c, s.online_info_stale)
                        };
                        if confirmed {
                            ui.colored_label(Color32::GREEN, t.campus_auth_confirmed);
                            if stale {
                                ui.colored_label(Color32::GRAY, t.online_info_stale_hint);
                            }
                        }
                    }
                    LoginState::PendingConfirm => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_pending_confirm).color(Color32::YELLOW));
                        let stale = {
                            let s = self.state.lock().unwrap();
                            s.online_info_stale
                        };
                        if stale {
                            ui.colored_label(Color32::GRAY, t.online_info_stale_hint);
                        }
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
                    if ui
                        .button(t.btn_delete)
                        .on_hover_text(t.hint_delete)
                        .clicked()
                    {
                        {
                            let mut s = self.state.lock().unwrap();
                            s.config.users.remove(user_idx);
                            s.user_statuses.remove(user_idx);
                            s.reconnect_targets.retain(|&i| i != user_idx);
                            for t in &mut s.reconnect_targets {
                                if *t > user_idx {
                                    *t -= 1;
                                }
                            }
                            s.add_log("[INFO] Removed user".to_string());
                        }
                        self.save_config();
                        return;
                    }

                    if ui.button(t.btn_edit).on_hover_text(t.hint_edit).clicked() {
                        let s = self.state.lock().unwrap();
                        if let Some(user) = s.config.users.get(user_idx) {
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

                    let is_busy = state == LoginState::LoggingIn || state == LoginState::LoggingOut;

                    if should_show_logout_button(&state) {
                        if ui
                            .add_enabled(!is_busy, egui::Button::new(t.btn_logout))
                            .clicked()
                        {
                            let state = self.state.clone();
                            tokio::spawn(async move {
                                auth::do_logout(state, user_idx).await;
                            });
                        }
                    } else {
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
                });
            });

            ui.horizontal(|ui| {
                ui.label(t.user_label);
                ui.label(RichText::new(&username).strong());
            });

            // Show server-confirmed auth details when applicable
            let confirmed_info = {
                let s = self.state.lock().unwrap();
                s.online_info
                    .as_ref()
                    .filter(|info| {
                        let mr = crate::service::online_info::match_account(
                            &info.user_name,
                            &s.config.users,
                        );
                        matches!(
                            mr,
                            crate::service::online_info::MatchResult::Exact(i)
                                | crate::service::online_info::MatchResult::UniqueBase(i)
                                if i == user_idx
                        )
                    })
                    .cloned()
            };

            if let Some(ref info) = confirmed_info {
                // Server confirmed this user is online — show auth details
                ui.label(format!("{} {}", t.ip_label, info.online_ip));

                let hours = info.sum_seconds / 3600;
                ui.label(format!("{} {}h", t.online_duration_label, hours));

                if info.remain_bytes > 0 {
                    ui.label(format!(
                        "{} {}",
                        t.remain_traffic_label,
                        crate::ui::format_bytes(info.remain_bytes)
                    ));
                }

                if !info.products_name.is_empty() {
                    ui.colored_label(
                        Color32::GRAY,
                        format!("{} {}", t.plan_label, info.products_name),
                    );
                }
            } else if !current_ip.is_empty() {
                ui.label(format!("{} {}", t.ip_label, current_ip));
            } else {
                let s = self.state.lock().unwrap();
                if let Some(user) = s.config.users.get(user_idx) {
                    if let Some(ref ip) = user.ip {
                        if !ip.is_empty() {
                            ui.label(format!(
                                "{} {}",
                                t.ip_label,
                                t.ip_configured.replace("{}", ip)
                            ));
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
                let candidates = crate::service::detection::detect_campus_ip_candidates();
                if let Some((name, _ip)) = candidates.first() {
                    self.edit_if_name = name.clone();
                }
                self.show_add_dialog = true;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let any_busy = {
                    let s = self.state.lock().unwrap();
                    s.user_statuses.iter().any(|us| {
                        us.state == LoginState::LoggingIn || us.state == LoginState::LoggingOut
                    })
                };

                if ui
                    .add_enabled(!any_busy, egui::Button::new(t.btn_login_all))
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_login(state).await });
                }
                if ui
                    .add_enabled(!any_busy, egui::Button::new(t.btn_logout_all))
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_logout(state).await });
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
                let pwd_hint = if is_new_user {
                    t.field_password_hint
                } else {
                    t.field_password_hint_edit
                };
                ui.add(
                    egui::TextEdit::singleline(&mut self.edit_password)
                        .password(true)
                        .hint_text(pwd_hint),
                );

                ui.label(t.field_ip);
                ui.text_edit_singleline(&mut self.edit_ip)
                    .on_hover_text(t.field_ip_hint);

                // Show current detected campus IP as readonly info
                let detected_ip = crate::service::detection::detect_campus_ip();
                if let Some(ref dip) = detected_ip {
                    ui.colored_label(Color32::GRAY, t.ip_detected.replace("{}", dip));
                }

                ui.label(t.field_if_name);
                ui.text_edit_singleline(&mut self.edit_if_name)
                    .on_hover_text(t.field_if_name_hint);

                let interfaces = get_network_interfaces();
                if !interfaces.is_empty() {
                    ui.label(t.available_interfaces);
                    for (name, ip) in &interfaces {
                        if ui.button(format!("  {} — {}", name, ip)).clicked() {
                            self.edit_if_name.clone_from(name);
                        }
                    }
                } else {
                    ui.colored_label(Color32::YELLOW, "No network interfaces detected");
                }

                ui.add_space(8.0);

                let can_save = if is_new_user {
                    !self.edit_username.is_empty() && !self.edit_password.is_empty()
                } else {
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
                            if let Some(idx) = self.editing_user_idx {
                                let s = self.state.lock().unwrap();
                                s.config
                                    .users
                                    .get(idx)
                                    .map(|u| u.encrypted_password.clone())
                                    .unwrap_or_default()
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
                                s.user_statuses.push(crate::service::UserStatus::new());
                                let uname = s.config.users.last().unwrap().username.clone();
                                s.add_log(format!("[INFO] Added user {}", uname));
                            }
                            s.ensure_statuses();
                        }

                        self.save_config();
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

    fn render_version_section(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let status = {
            let s = self.state.lock().unwrap();
            s.update_status.clone()
        };

        let busy = matches!(
            status,
            UpdateStatus::Checking
                | UpdateStatus::Downloading
                | UpdateStatus::PreparingUpdate
                | UpdateStatus::Restarting
        );

        ui.horizontal(|ui| {
            ui.label(format!(
                "{} v{}",
                t.version_label,
                env!("CARGO_PKG_VERSION")
            ));

            if ui
                .add_enabled(!busy, egui::Button::new(t.btn_check_update))
                .clicked()
            {
                let state = self.state.clone();
                {
                    let mut s = self.state.lock().unwrap();
                    s.update_status = UpdateStatus::Checking;
                }
                crate::service::request_ui_repaint();
                tokio::spawn(async move {
                    match crate::service::update::check_update().await {
                        Ok(Some((latest, _release_url, download_url))) => {
                            {
                                let mut s = state.lock().unwrap();
                                s.add_log(format!(
                                    "[INFO] New version {} found, starting automatic update",
                                    latest
                                ));
                            }
                            crate::service::request_ui_repaint();
                            crate::service::update::perform_update(state, latest, download_url)
                                .await;
                        }
                        Ok(None) => {
                            let mut s = state.lock().unwrap();
                            s.update_status = UpdateStatus::UpToDate;
                            crate::service::request_ui_repaint();
                        }
                        Err(e) => {
                            let mut s = state.lock().unwrap();
                            s.update_status = UpdateStatus::Failed(e);
                            crate::service::request_ui_repaint();
                        }
                    }
                });
            }
        });

        ui.horizontal(|ui| match &status {
            UpdateStatus::Idle => {}
            UpdateStatus::Checking => {
                ui.colored_label(Color32::GRAY, t.update_checking);
            }
            UpdateStatus::UpToDate => {
                ui.colored_label(Color32::GREEN, t.update_up_to_date);
            }
            UpdateStatus::Available {
                latest,
                release_url,
                download_url,
            } => {
                ui.colored_label(Color32::YELLOW, t.update_available.replace("{}", latest));
                ui.add_space(4.0);

                if ui.button(t.btn_auto_update).clicked() {
                    let state = self.state.clone();
                    let ver = latest.clone();
                    let url = download_url.clone();
                    tokio::spawn(async move {
                        crate::service::update::perform_update(state, ver, url).await;
                    });
                }

                if ui.button(t.btn_open_release).clicked() {
                    let _ = std::process::Command::new("cmd")
                        .args(["/c", "start", "", release_url.as_str()])
                        .spawn();
                }
            }
            UpdateStatus::Downloading => {
                ui.colored_label(Color32::YELLOW, t.update_downloading);
            }
            UpdateStatus::PreparingUpdate => {
                ui.colored_label(Color32::YELLOW, t.update_preparing);
            }
            UpdateStatus::Restarting => {
                ui.colored_label(Color32::GREEN, t.update_restarting);
            }
            UpdateStatus::Failed(e) => {
                ui.colored_label(Color32::RED, format!("{}: {}", t.update_failed, e));
            }
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.collapsing(t.section_settings, |ui| {
            let (
                mut auto_reconnect,
                mut minimize_to_tray,
                mut auto_start,
                mut enable_ipv4_internet_probe,
                mut detect_ip,
                mut strict_bind,
                mut double_stack,
                mut monitor_interval,
                mut retry_times,
                mut retry_delay,
                mut n,
                mut utype,
                mut acid,
                mut os,
                mut name,
            ) = {
                let s = self.state.lock().unwrap();
                let c = &s.config;
                (
                    c.auto_reconnect,
                    c.minimize_to_tray,
                    c.auto_start,
                    c.enable_ipv4_internet_probe,
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
                changed |= ui
                    .add(egui::DragValue::new(&mut n).range(1..=999))
                    .changed();
                ui.label(t.label_type);
                changed |= ui
                    .add(egui::DragValue::new(&mut utype).range(1..=99))
                    .changed();
                ui.label(t.label_acid);
                changed |= ui
                    .add(egui::DragValue::new(&mut acid).range(1..=999))
                    .changed();
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
            changed |= ui
                .checkbox(&mut auto_reconnect, t.opt_auto_reconnect)
                .changed();
            changed |= ui
                .checkbox(&mut minimize_to_tray, t.opt_minimize_tray)
                .changed();

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

            changed |= ui
                .checkbox(&mut enable_ipv4_internet_probe, t.enable_ipv4_probe)
                .on_hover_text(t.enable_ipv4_probe_hint)
                .changed();

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
                    s.config.enable_ipv4_internet_probe = enable_ipv4_internet_probe;
                    if !enable_ipv4_internet_probe {
                        s.ipv4_internet = Ipv4InternetStatus::Disabled;
                    } else if s.ipv4_internet == Ipv4InternetStatus::Disabled {
                        s.ipv4_internet = Ipv4InternetStatus::Checking;
                    }
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
                self.save_config();
            }
        });
    }

    fn render_log(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        crate::ui::log_panel::render_log_panel(&self.state, ui, &t);
    }

    fn save_config(&self) {
        let result = {
            let s = self.state.lock().unwrap();
            write_config(config_path(), &s.config)
        };
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
        // Capture HWND + egui context on first frame
        capture_main_hwnd();
        crate::service::set_egui_ctx(ctx.clone());

        // Sync eframe visibility state after native_show_window() was called
        // from the listener thread. Without this, eframe/winit still thinks the
        // window is invisible, so the next Visible(false) is a no-op.
        if SYNC_VISIBLE.swap(false, Ordering::SeqCst) {
            tracing::info!("[MainLoop] Syncing eframe visibility state after native show");
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        }

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
                // Also native hide to ensure symmetry with native_show_window()
                if let Some(&hwnd) = MAIN_HWND.get() {
                    unsafe {
                        ShowWindow(hwnd, SW_HIDE);
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_button_for_online() {
        assert!(should_show_logout_button(&LoginState::Online));
    }

    #[test]
    fn logout_button_for_pending_confirm() {
        assert!(should_show_logout_button(&LoginState::PendingConfirm));
    }

    #[test]
    fn login_button_for_error() {
        assert!(!should_show_logout_button(&LoginState::Error));
    }

    #[test]
    fn login_button_for_logged_out() {
        assert!(!should_show_logout_button(&LoginState::LoggedOut));
    }

    #[test]
    fn busy_button_for_logging_in() {
        assert!(!should_show_logout_button(&LoginState::LoggingIn));
    }

    #[test]
    fn busy_button_for_logging_out() {
        assert!(!should_show_logout_button(&LoginState::LoggingOut));
    }
}
