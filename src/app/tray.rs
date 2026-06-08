use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::icon::create_tray_icon_rgba;
use crate::path::config_path;
use crate::service::auth;
use crate::service::config::write_config;
use crate::service::{LoginState, SharedState};
use crate::ui::l10n::UiText;

static MAIN_HWND: OnceLock<isize> = OnceLock::new();
pub(crate) static FORCE_QUIT: AtomicBool = AtomicBool::new(false);

/// Set by native_show_window() so the next update() can sync eframe's
/// viewport state after native ShowWindow bypasses winit tracking.
static SYNC_VISIBLE: AtomicBool = AtomicBool::new(false);

pub(super) fn capture_main_hwnd() {
    if MAIN_HWND.get().is_some() {
        return;
    }
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
        SYNC_VISIBLE.store(true, Ordering::SeqCst);
    } else {
        tracing::warn!("[Native] ShowWindow failed: no HWND captured yet");
    }
}

fn native_force_quit(state: &SharedState) {
    tracing::info!("[Native] Force quit from tray");
    let config = if let Ok(mut s) = state.lock() {
        s.add_log("[INFO] Quit from tray menu".to_string());
        Some(s.config.clone())
    } else {
        None
    };
    if let Some(config) = config {
        if let Err(e) = write_config(config_path(), &config) {
            tracing::error!("Failed to save config on quit: {}", e);
        }
    }
    tracing::info!("[Native] Config saved, initiating quit");
    FORCE_QUIT.store(true, Ordering::SeqCst);
    if let Some(&hwnd) = MAIN_HWND.get() {
        tracing::info!("[Native] Posting WM_CLOSE to hwnd={}", hwnd);
        unsafe {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
    }
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        tracing::info!("[Native] Fallback: calling process::exit(0)");
        std::process::exit(0);
    });
}

pub(super) fn sync_visible_after_native_show(ctx: &egui::Context) {
    if SYNC_VISIBLE.swap(false, Ordering::SeqCst) {
        tracing::info!("[MainLoop] Syncing eframe visibility state after native show");
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    }
}

pub(super) fn hide_window() {
    if let Some(&hwnd) = MAIN_HWND.get() {
        unsafe {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}

pub(super) fn create_tray_icon(state: SharedState, t: &UiText) -> Option<TrayIcon> {
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

    match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(create_tray_icon_rgba())
        .with_tooltip(t.tray_tooltip)
        .build()
    {
        Ok(icon) => {
            tracing::info!("Tray icon created successfully");
            spawn_tray_listener(state, show_id, login_all_id, logout_all_id, quit_id);
            Some(icon)
        }
        Err(e) => {
            tracing::error!("Failed to create tray icon: {}. Tray features disabled.", e);
            if let Ok(mut s) = state.lock() {
                s.add_log(format!(
                    "[WARN] System tray unavailable: {}. Minimize-to-tray disabled.",
                    e
                ));
            }
            None
        }
    }
}

fn spawn_tray_listener(
    state: SharedState,
    show_id: tray_icon::menu::MenuId,
    login_all_id: tray_icon::menu::MenuId,
    logout_all_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
) {
    let tokio_handle = tokio::runtime::Handle::current();

    std::thread::spawn(move || {
        let menu_rx = MenuEvent::receiver();
        let tray_rx = TrayIconEvent::receiver();
        tracing::info!("[TrayListener] Thread started, listening for MenuEvent + TrayIconEvent...");

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
                                    let mut s = state.lock().unwrap();
                                    s.add_log("[INFO] Tray menu: show window".to_string());
                                }
                                native_show_window();
                            } else if id == login_all_id {
                                tracing::info!("[TrayListener] → OneClickLogin");
                                {
                                    let mut s = state.lock().unwrap();
                                    s.add_log("[INFO] One-click login requested from tray".to_string());
                                    let count = s.config.users.len().min(s.user_statuses.len());
                                    if count > 0 {
                                        for i in 0..count {
                                            if s.user_statuses[i].state != LoginState::Online {
                                                s.user_statuses[i].state = LoginState::LoggedOut;
                                                s.user_statuses[i].last_error.clear();
                                            }
                                        }
                                    }
                                }
                                crate::service::request_ui_repaint();
                                let st = state.clone();
                                tokio_handle.spawn(async move {
                                    tracing::info!("[OneClickLogin] Task started from tray");
                                    auth::do_one_click_login(st).await;
                                    tracing::info!("[OneClickLogin] Task completed");
                                });
                            } else if id == logout_all_id {
                                tracing::info!("[TrayListener] → OneClickLogout");
                                {
                                    let mut s = state.lock().unwrap();
                                    s.add_log("[INFO] One-click logout requested from tray".to_string());
                                }
                                crate::service::request_ui_repaint();
                                let st = state.clone();
                                tokio_handle.spawn(async move {
                                    tracing::info!("[OneClickLogout] Task started from tray");
                                    auth::do_one_click_logout(st).await;
                                    tracing::info!("[OneClickLogout] Task completed");
                                });
                            } else if id == quit_id {
                                tracing::info!("[TrayListener] → Quit");
                                native_force_quit(&state);
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
                                        let mut s = state.lock().unwrap();
                                        s.add_log("[INFO] Tray left-click: show window".to_string());
                                    }
                                    native_show_window();
                                }
                                TrayIconEvent::DoubleClick { button, .. } => {
                                    if matches!(button, tray_icon::MouseButton::Left) {
                                        tracing::info!("[TrayListener] Left double-click → show window");
                                        {
                                            let mut s = state.lock().unwrap();
                                            s.add_log("[INFO] Tray double-click: show window".to_string());
                                        }
                                        native_show_window();
                                    }
                                }
                                _ => {}
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
}

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
