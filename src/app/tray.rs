use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::icon::create_tray_icon_rgba;
use crate::path::config_path;
use crate::service::auth;
use crate::service::config::save_shared_config;
use crate::service::SharedState;
use crate::ui::l10n::UiText;

static MAIN_HWND: OnceLock<isize> = OnceLock::new();
pub(crate) static FORCE_QUIT: AtomicBool = AtomicBool::new(false);

/// The listener posts a native message; the UI thread owns window visibility.
static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

// Only the first two fields of Win32 MSG are needed by the winit hook.
#[repr(C)]
struct NativeMessageHeader {
    hwnd: isize,
    message: u32,
}

#[repr(C)]
#[derive(Default)]
struct NativeRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl NativeRect {
    fn size(&self) -> [i32; 2] {
        [
            self.right.saturating_sub(self.left),
            self.bottom.saturating_sub(self.top),
        ]
    }
}

#[repr(C)]
#[derive(Default)]
struct WindowPlacement {
    length: u32,
    flags: u32,
    show_cmd: u32,
    min_position: [i32; 2],
    max_position: [i32; 2],
    normal_position: NativeRect,
}

/// Run restoration before egui painting, including when its client size is zero.
pub(crate) fn install_window_restore_hook(
    builder: &mut eframe::EventLoopBuilder<eframe::UserEvent>,
    state: SharedState,
) {
    use winit::platform::windows::EventLoopBuilderExtWindows;
    builder.with_msg_hook(move |message| {
        if message.is_null() {
            return false;
        }
        // winit supplies a valid MSG for this UI-thread callback.
        let message = unsafe { &*message.cast::<NativeMessageHeader>() };
        if message.message != WM_RESTORE_FROM_TRAY || MAIN_HWND.get() != Some(&message.hwnd) {
            return false;
        }
        if SHOW_REQUESTED.load(Ordering::Acquire) && !FORCE_QUIT.load(Ordering::SeqCst) {
            let restore_size = state
                .try_lock()
                .map(|s| super::window::startup_size(s.config.window_width, s.config.window_height))
                .unwrap_or(super::window::DEFAULT_SIZE);
            show_window(restore_size);
            // Leave SHOW_REQUESTED for update() to sync egui's visibility and
            // cancel an older close-to-tray event. A consumed request is ignored.
            unsafe {
                InvalidateRect(message.hwnd, std::ptr::null(), 0);
            }
            crate::service::request_ui_repaint();
        }
        true
    });
}

pub(crate) fn capture_main_hwnd(window: &impl winit::raw_window_handle::HasWindowHandle) {
    use winit::raw_window_handle::RawWindowHandle;
    if MAIN_HWND.get().is_some() {
        return;
    }
    if let Ok(RawWindowHandle::Win32(handle)) = window.window_handle().map(|handle| handle.as_raw())
    {
        let hwnd = handle.hwnd.get();
        let _ = MAIN_HWND.set(hwnd);
        tracing::info!("[Native] Captured main window HWND={}", hwnd);
    }
}

fn request_show_window() {
    SHOW_REQUESTED.store(true, Ordering::Release);
    if let Some(&hwnd) = MAIN_HWND.get() {
        unsafe {
            // A private message reaches the UI loop even without a paintable
            // client area. WM_PAINT alone cannot repair its window geometry.
            if PostMessageW(hwnd, WM_RESTORE_FROM_TRAY, 0, 0) == 0 {
                tracing::warn!("[Native] Could not queue window restoration");
            }
        }
    }
    crate::service::request_ui_repaint();
}

pub(super) fn take_show_request() -> bool {
    SHOW_REQUESTED.swap(false, Ordering::AcqRel)
}

/// Called only on the UI thread, from the message hook or App::update().
pub(super) fn show_window(restore_size: [f32; 2]) {
    if FORCE_QUIT.load(Ordering::SeqCst) {
        return;
    }
    if let Some(&hwnd) = MAIN_HWND.get() {
        tracing::info!("[Native] ShowWindow: hwnd={}", hwnd);
        unsafe {
            // SW_RESTORE unmaximizes an already-maximized window. Use it only
            // when iconic, preserving the state from before minimization.
            ShowWindow(
                hwnd,
                if IsIconic(hwnd) != 0 {
                    SW_RESTORE
                } else {
                    SW_SHOW
                },
            );
            repair_collapsed_window(hwnd, restore_size);
            SetForegroundWindow(hwnd);
        }
    } else {
        tracing::warn!("[Native] ShowWindow failed: no HWND captured yet");
    }
}

fn repair_collapsed_window(hwnd: isize, restore_size: [f32; 2]) -> bool {
    unsafe {
        if IsIconic(hwnd) != 0 {
            return false;
        }
        let dpi = GetDpiForWindow(hwnd);
        if dpi == 0 {
            return false;
        }
        let maximized = IsZoomed(hwnd) != 0;
        let mut placement = WindowPlacement {
            length: std::mem::size_of::<WindowPlacement>() as u32,
            ..Default::default()
        };
        let client_size = if maximized {
            // A healthy maximized client can still hide corrupt restore bounds.
            if GetWindowPlacement(hwnd, &mut placement) == 0 {
                return false;
            }
            let Some(frame) = outer_size(hwnd, [0, 0], dpi) else {
                return false;
            };
            let normal = placement.normal_position.size();
            [
                normal[0].saturating_sub(frame[0]),
                normal[1].saturating_sub(frame[1]),
            ]
        } else {
            let mut client = NativeRect::default();
            if GetClientRect(hwnd, &mut client) == 0 {
                return false;
            }
            client.size()
        };
        let Some([width, height]) =
            super::window::native_recovery_size(client_size, dpi, restore_size)
        else {
            return false;
        };
        let Some([outer_width, outer_height]) = outer_size(hwnd, [width, height], dpi) else {
            return false;
        };
        let repaired = if maximized {
            let Some(right) = placement.normal_position.left.checked_add(outer_width) else {
                return false;
            };
            let Some(bottom) = placement.normal_position.top.checked_add(outer_height) else {
                return false;
            };
            placement.normal_position.right = right;
            placement.normal_position.bottom = bottom;
            // SetWindowPlacement may show hidden windows; preserve visibility.
            if IsWindowVisible(hwnd) == 0 {
                placement.show_cmd = SW_HIDE as u32;
            }
            SetWindowPlacement(hwnd, &placement)
        } else {
            SetWindowPos(
                hwnd,
                0,
                0,
                0,
                outer_width,
                outer_height,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
        if repaired == 0 {
            tracing::warn!("[Native] Could not repair collapsed window size");
            return false;
        }
        tracing::info!(
            "[Native] Repaired collapsed geometry {:?} to {}x{} at DPI {} (maximized={})",
            client_size,
            width,
            height,
            dpi,
            maximized
        );
        true
    }
}

fn outer_size(hwnd: isize, client: [i32; 2], dpi: u32) -> Option<[i32; 2]> {
    let mut outer = NativeRect {
        right: client[0],
        bottom: client[1],
        ..Default::default()
    };
    unsafe {
        if AdjustWindowRectExForDpi(
            &mut outer,
            GetWindowLongW(hwnd, GWL_STYLE) as u32,
            i32::from(GetMenu(hwnd) != 0),
            GetWindowLongW(hwnd, GWL_EXSTYLE) as u32,
            dpi,
        ) == 0
        {
            tracing::warn!("[Native] Could not calculate restored window bounds");
            return None;
        }
    }
    Some(outer.size())
}

fn native_force_quit(state: &SharedState) {
    tracing::info!("[Native] Force quit from tray");
    if let Ok(mut s) = state.lock() {
        s.add_log("[INFO] Quit from tray menu".to_string());
    }
    if let Err(e) = save_shared_config(config_path(), state) {
        tracing::error!("Failed to save config on quit: {}", e);
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
                                request_show_window();
                            } else if id == login_all_id {
                                tracing::info!("[TrayListener] → OneClickLogin");
                                {
                                    let mut s = state.lock().unwrap();
                                    s.add_log("[INFO] One-click login requested from tray".to_string());
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
                                    request_show_window();
                                }
                                TrayIconEvent::DoubleClick { button, .. } => {
                                    if matches!(button, tray_icon::MouseButton::Left) {
                                        tracing::info!("[TrayListener] Left double-click → show window");
                                        {
                                            let mut s = state.lock().unwrap();
                                            s.add_log("[INFO] Tray double-click: show window".to_string());
                                        }
                                        request_show_window();
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
    fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
    fn IsIconic(hwnd: isize) -> i32;
    fn IsZoomed(hwnd: isize) -> i32;
    fn IsWindowVisible(hwnd: isize) -> i32;
    fn GetWindowPlacement(hwnd: isize, placement: *mut WindowPlacement) -> i32;
    fn SetWindowPlacement(hwnd: isize, placement: *const WindowPlacement) -> i32;
    fn GetClientRect(hwnd: isize, rect: *mut NativeRect) -> i32;
    fn GetDpiForWindow(hwnd: isize) -> u32;
    fn GetWindowLongW(hwnd: isize, index: i32) -> i32;
    fn GetMenu(hwnd: isize) -> isize;
    fn AdjustWindowRectExForDpi(
        rect: *mut NativeRect,
        style: u32,
        menu: i32,
        ex_style: u32,
        dpi: u32,
    ) -> i32;
    fn SetWindowPos(
        hwnd: isize,
        insert_after: isize,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        flags: u32,
    ) -> i32;
    fn SetForegroundWindow(hwnd: isize) -> i32;
    fn PostMessageW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> i32;
    fn InvalidateRect(hwnd: isize, rect: *const NativeRect, erase: i32) -> i32;
}

const SW_HIDE: i32 = 0;
#[cfg(target_os = "windows")]
const SW_SHOW: i32 = 5;
#[cfg(target_os = "windows")]
const SW_RESTORE: i32 = 9;
#[cfg(target_os = "windows")]
const WM_CLOSE: u32 = 0x0010;
const WM_RESTORE_FROM_TRAY: u32 = 0x8000 + 0x438;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;

#[cfg(test)]
mod tests {
    use super::*;

    // This fixture is never shown and does not use MAIN_HWND or the app state.
    struct HiddenWindow(isize);

    impl HiddenWindow {
        fn new(style: u32) -> Self {
            let class: Vec<_> = "STATIC\0".encode_utf16().collect();
            let title: Vec<_> = "CampusNet offline geometry fixture\0"
                .encode_utf16()
                .collect();
            let window = Self(unsafe {
                CreateWindowExW(
                    0,
                    class.as_ptr(),
                    title.as_ptr(),
                    style,
                    20,
                    20,
                    1200,
                    900,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                )
            });
            assert_ne!(window.0, 0, "could not create hidden geometry fixture");
            assert_eq!(unsafe { IsWindowVisible(window.0) }, 0);
            window
        }
    }

    impl Drop for HiddenWindow {
        fn drop(&mut self) {
            unsafe {
                DestroyWindow(self.0);
            }
        }
    }

    extern "system" {
        fn CreateWindowExW(
            ex_style: u32,
            class: *const u16,
            title: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: isize,
            menu: isize,
            instance: isize,
            param: *mut std::ffi::c_void,
        ) -> isize;
        fn DestroyWindow(hwnd: isize) -> i32;
        fn GetWindowRect(hwnd: isize, rect: *mut NativeRect) -> i32;
    }

    #[test]
    fn hidden_native_window_recovers_client_and_normal_restore_bounds() {
        let style = 0x00CF0000; // WS_OVERLAPPEDWINDOW, without WS_VISIBLE.
        unsafe {
            let window = HiddenWindow::new(style);
            let mut before = NativeRect::default();
            assert_ne!(GetWindowRect(window.0, &mut before), 0);
            assert!(!repair_collapsed_window(window.0, [800.0, 600.0]));
            let mut after = NativeRect::default();
            assert_ne!(GetWindowRect(window.0, &mut after), 0);
            assert_eq!(before.size(), after.size());

            let dpi = GetDpiForWindow(window.0);
            assert_ne!(dpi, 0);
            let mut frame = NativeRect::default();
            assert_ne!(AdjustWindowRectExForDpi(&mut frame, style, 0, 0, dpi), 0);
            let [width, height] = frame.size();
            assert_ne!(
                SetWindowPos(
                    window.0,
                    0,
                    0,
                    0,
                    width,
                    height,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE
                ),
                0
            );
            let mut client = NativeRect::default();
            assert_ne!(GetClientRect(window.0, &mut client), 0);
            // DefWindowProc enforces a caption's minimum width; a zero-height
            // client still exercises recovery of unusable native geometry.
            assert_eq!(client.size()[1], 0);

            assert!(repair_collapsed_window(window.0, [800.0, 600.0]));
            assert_ne!(GetClientRect(window.0, &mut client), 0);
            assert_eq!(
                client.size(),
                super::super::window::native_recovery_size([0, 0], dpi, [800.0, 600.0]).unwrap()
            );
            assert_ne!(GetWindowRect(window.0, &mut after), 0);
            assert_eq!([before.left, before.top], [after.left, after.top]);
            let mut placement = WindowPlacement {
                length: std::mem::size_of::<WindowPlacement>() as u32,
                ..Default::default()
            };
            assert_ne!(GetWindowPlacement(window.0, &mut placement), 0);
            assert_eq!(placement.normal_position.size(), after.size());
            assert!(!repair_collapsed_window(window.0, [800.0, 600.0]));
            assert_eq!(IsWindowVisible(window.0), 0);
        }
    }

    #[test]
    fn hidden_maximized_window_repairs_normal_bounds_without_unmaximizing() {
        let style = 0x00CF0000;
        unsafe {
            let window = HiddenWindow::new(style | 0x01000000); // WS_MAXIMIZE.
            assert_ne!(IsZoomed(window.0), 0);
            let dpi = GetDpiForWindow(window.0);
            let mut frame = NativeRect::default();
            assert_ne!(AdjustWindowRectExForDpi(&mut frame, style, 0, 0, dpi), 0);
            let mut placement = WindowPlacement {
                length: std::mem::size_of::<WindowPlacement>() as u32,
                ..Default::default()
            };
            assert_ne!(GetWindowPlacement(window.0, &mut placement), 0);
            let position = [
                placement.normal_position.left,
                placement.normal_position.top,
            ];
            placement.normal_position.right = placement.normal_position.left + frame.size()[0];
            placement.normal_position.bottom = placement.normal_position.top + frame.size()[1];
            placement.show_cmd = 0; // SW_HIDE: the fixture must never be shown.
            assert_ne!(SetWindowPlacement(window.0, &placement), 0);
            assert_ne!(IsZoomed(window.0), 0);
            assert_eq!(IsWindowVisible(window.0), 0);

            assert!(repair_collapsed_window(window.0, [800.0, 600.0]));
            assert_ne!(IsZoomed(window.0), 0);
            assert_eq!(IsWindowVisible(window.0), 0);
            assert_ne!(GetWindowPlacement(window.0, &mut placement), 0);
            assert_eq!(
                [
                    placement.normal_position.left,
                    placement.normal_position.top
                ],
                position
            );
            let pixels =
                super::super::window::native_recovery_size([0, 0], dpi, [800.0, 600.0]).unwrap();
            assert_eq!(
                placement.normal_position.size(),
                [pixels[0] + frame.size()[0], pixels[1] + frame.size()[1]]
            );
            assert!(!repair_collapsed_window(window.0, [800.0, 600.0]));
        }
    }
}
