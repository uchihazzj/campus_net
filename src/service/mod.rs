use std::sync::{Arc, Mutex, OnceLock};

use crate::service::config::AppConfig;
pub use crate::service::online_info::OnlineUserInfo;
pub use crate::service::update::UpdateStatus;

// ── UI repaint signal ──────────────────────────────────
// Stored egui::Context for triggering immediate repaints
// from background threads (e.g. tray listener → auth task).
static EGUI_CTX: OnceLock<egui::Context> = OnceLock::new();

/// Called once from the main thread to store the egui context.
pub fn set_egui_ctx(ctx: egui::Context) {
    let _ = EGUI_CTX.set(ctx);
}

/// Trigger an immediate UI repaint. Safe to call from any thread.
/// No-op if set_egui_ctx hasn't been called yet.
pub fn request_ui_repaint() {
    if let Some(ctx) = EGUI_CTX.get() {
        ctx.request_repaint();
    }
}

pub mod auth;
pub mod config;
pub mod detection;
pub mod http_client;
pub mod monitor;
pub mod online_info;
pub mod update;
pub mod update_scheduler;

#[derive(Debug, Clone, PartialEq)]
pub enum LoginState {
    LoggedOut,
    LoggingIn,
    /// Login request succeeded at the portal (srun_portal), but the
    /// server (rad_user_info) has not yet confirmed the session.
    /// UI must not show "confirmed" in this state.
    PendingConfirm,
    /// Server (rad_user_info) has confirmed this user is online.
    Online,
    LoggingOut,
    Error,
}

/// Reachability of the Srun auth server itself (e.g., http://10.0.0.55).
/// Only reflects whether the auth server endpoint responds — not whether
/// the user is logged in, and not whether the public internet is reachable.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthServerStatus {
    Reachable,
    Unreachable,
    Unknown,
}

/// Campus auth login state. Determined by captive-portal probe (HTTP redirect
/// detection), not by whether the auth server or public internet is reachable.
#[derive(Debug, Clone, PartialEq)]
pub enum CampusAuthStatus {
    LoggedIn,
    NotLoggedIn,
    Unknown,
}

/// IPv4-only internet reachability. All probes bind to the campus IPv4
/// address to avoid false positives from IPv6 connectivity.
#[derive(Debug, Clone, PartialEq)]
pub enum Ipv4InternetStatus {
    Checking,
    Reachable,
    CaptivePortal,
    Unreachable,
    /// All probes failed — could not determine reachability (e.g., DNS failure
    /// on all endpoints, or client build error). Different from Unreachable,
    /// which means we confirmed IPv4 is down.
    ProbeFailed,
    /// IPv4 internet probe is disabled by user config.
    Disabled,
}

#[derive(Debug, Clone)]
pub struct UserStatus {
    pub state: LoginState,
    pub current_ip: String,
    pub last_error: String,
}

impl UserStatus {
    pub fn new() -> Self {
        Self {
            state: LoginState::LoggedOut,
            current_ip: String::new(),
            last_error: String::new(),
        }
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub user_statuses: Vec<UserStatus>,
    pub log_messages: Vec<String>,
    // Four-layer detection state
    pub campus_ip: Option<String>,
    pub auth_server: AuthServerStatus,
    pub campus_auth: CampusAuthStatus,
    pub ipv4_internet: Ipv4InternetStatus,
    // Consecutive failure counters
    pub internet_fail_count: u32,
    /// User indices to reconnect on next auto-reconnect cycle.
    /// Populated on first trouble detection, cleared on success
    /// or when user manually logs out.
    pub reconnect_targets: Vec<usize>,
    /// Latest result from rad_user_info query. None if never queried or not logged in.
    pub online_info: Option<OnlineUserInfo>,
    /// Consecutive failures of rad_user_info query (request timeout, parse error).
    pub online_info_fail_count: u32,
    /// True when rad_user_info query has failed at least once since last success.
    /// The last online_info is preserved but may not reflect current server state.
    pub online_info_stale: bool,
    /// True after user manually logs out. Suppresses auto-reconnect until user
    /// manually logs in. Not persisted to config — runtime-only.
    pub suppress_auto_reconnect: bool,
    pub update_status: UpdateStatus,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let user_count = config.users.len();
        let probe_enabled = config.enable_ipv4_internet_probe;
        Self {
            config,
            user_statuses: vec![UserStatus::new(); user_count],
            log_messages: Vec::new(),
            campus_ip: None,
            auth_server: AuthServerStatus::Unknown,
            campus_auth: CampusAuthStatus::Unknown,
            ipv4_internet: if probe_enabled {
                Ipv4InternetStatus::Checking
            } else {
                Ipv4InternetStatus::Disabled
            },
            internet_fail_count: 0,
            reconnect_targets: Vec::new(),
            online_info: None,
            online_info_fail_count: 0,
            online_info_stale: false,
            suppress_auto_reconnect: false,
            update_status: UpdateStatus::Idle,
        }
    }

    pub fn add_log(&mut self, msg: String) {
        let stamped = format!("[{}] {}", current_ui_log_time(), msg);
        self.log_messages.push(stamped);
        if self.log_messages.len() > 200 {
            self.log_messages.remove(0);
        }
    }

    pub fn ensure_statuses(&mut self) {
        while self.user_statuses.len() < self.config.users.len() {
            self.user_statuses.push(UserStatus::new());
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

fn current_ui_log_time() -> String {
    chrono::Local::now().format("%m/%d %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::config::AppConfig;

    fn format_ui_log_message(now: chrono::DateTime<chrono::Local>, msg: &str) -> String {
        format!("[{}] {}", now.format("%m/%d %H:%M"), msg)
    }

    #[test]
    fn add_log_prepends_timestamp() {
        let mut s = AppState::new(AppConfig::default());
        s.add_log("[INFO] test".to_string());
        let entry = &s.log_messages[0];
        // Format: [MM/DD HH:MM] [INFO] test
        assert!(entry.starts_with('['));
        assert!(entry.contains("] [INFO] test"));
        // Check MM/DD HH:MM pattern
        let after_bracket = &entry[1..];
        let parts: Vec<&str> = after_bracket.splitn(2, "] ").collect();
        assert_eq!(parts.len(), 2);
        let time_part = parts[0];
        let date_time: Vec<&str> = time_part.split(' ').collect();
        assert_eq!(date_time.len(), 2);
        let date: Vec<&str> = date_time[0].split('/').collect();
        assert_eq!(date.len(), 2);
        let time: Vec<&str> = date_time[1].split(':').collect();
        assert_eq!(time.len(), 2);
        // All parts should parse as u32
        date[0].parse::<u32>().unwrap();
        date[1].parse::<u32>().unwrap();
        time[0].parse::<u32>().unwrap();
        time[1].parse::<u32>().unwrap();
    }

    #[test]
    fn add_log_caps_at_200() {
        let mut s = AppState::new(AppConfig::default());
        for i in 0..250 {
            s.add_log(format!("msg {}", i));
        }
        assert_eq!(s.log_messages.len(), 200);
        // Oldest message removed, so first entry should be "msg 50"
        assert!(s.log_messages[0].contains("msg 50"));
        assert!(s.log_messages[199].contains("msg 249"));
    }

    #[test]
    fn format_ui_log_message_includes_timestamp() {
        use chrono::Datelike;
        use chrono::Timelike;

        let dt = chrono::Local::now()
            .with_month(6)
            .and_then(|d| d.with_day(1))
            .and_then(|d| d.with_hour(20))
            .and_then(|d| d.with_minute(31))
            .and_then(|d| d.with_second(0))
            .and_then(|d| d.with_nanosecond(0))
            .unwrap();
        let result = format_ui_log_message(dt, "[INFO] test");
        assert_eq!(result, "[06/01 20:31] [INFO] test");
    }
}
