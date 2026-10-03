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
pub mod user_ip;

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
    /// One authentication operation owns all accounts until it completes.
    pub auth_busy: bool,
    pub auth_generation: u64,
    pub online_query_generation: u64,
    pub online_query_busy: bool,
    pub config_save_pending: bool,
    pub autostart_busy: bool,
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
            auth_busy: false,
            auth_generation: 0,
            online_query_generation: 0,
            online_query_busy: false,
            config_save_pending: false,
            autostart_busy: false,
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

    pub fn authentication_busy(&self) -> bool {
        self.auth_busy
            || self
                .user_statuses
                .iter()
                .any(|us| matches!(us.state, LoginState::LoggingIn | LoginState::LoggingOut))
    }

    pub fn invalidate_auth_context(&mut self) {
        self.auth_generation = self.auth_generation.wrapping_add(1);
        self.online_query_generation = self.online_query_generation.wrapping_add(1);
        self.online_query_busy = false;
    }

    pub fn set_server(&mut self, server: String) -> bool {
        if self.authentication_busy() || self.config.server == server {
            return false;
        }
        let same_endpoint =
            crate::core::srun::SrunClient::normalize_server_url(&self.config.server)
                == crate::core::srun::SrunClient::normalize_server_url(&server);
        self.config.server = server;
        self.invalidate_auth_context();
        if !same_endpoint {
            self.user_statuses = vec![UserStatus::new(); self.config.users.len()];
            self.invalidate_online_info();
            self.auth_server = AuthServerStatus::Unknown;
            self.reconnect_targets.clear();
            self.internet_fail_count = 0;
            self.ipv4_internet = if self.config.enable_ipv4_internet_probe {
                Ipv4InternetStatus::Checking
            } else {
                Ipv4InternetStatus::Disabled
            };
        }
        true
    }

    fn invalidate_online_info(&mut self) {
        self.online_info = None;
        self.online_info_stale = true;
        self.online_info_fail_count = 0;
        self.campus_auth = CampusAuthStatus::Unknown;
    }

    fn invalidate_user_online_info(&mut self, idx: usize) {
        let related =
            self.online_info.as_ref().is_some_and(|info| {
                match online_info::match_account(&info.user_name, &self.config.users) {
                    online_info::MatchResult::Exact(i)
                    | online_info::MatchResult::UniqueBase(i) => i == idx,
                    online_info::MatchResult::Ambiguous(indices) => indices.contains(&idx),
                    online_info::MatchResult::NoMatch => false,
                }
            });
        if related {
            self.invalidate_online_info();
        }
    }

    pub fn current_online_info(&self) -> Option<&OnlineUserInfo> {
        if self.online_info_stale || self.campus_auth != CampusAuthStatus::LoggedIn {
            return None;
        }
        self.online_info.as_ref()
    }

    pub fn definitely_offline(&self) -> bool {
        self.campus_auth == CampusAuthStatus::NotLoggedIn
            || (self.online_info_fail_count >= 3
                && self.config.enable_ipv4_internet_probe
                && self.ipv4_internet == Ipv4InternetStatus::CaptivePortal)
    }

    pub fn confirmed_user_info(&self, idx: usize) -> Option<&OnlineUserInfo> {
        if self.user_statuses.get(idx)?.state != LoginState::Online {
            return None;
        }
        let info = self.current_online_info()?;
        (online_info::confirmed_online_user_idx(Some(info), &self.config.users) == Some(idx))
            .then_some(info)
    }

    pub fn replace_user(&mut self, idx: usize, user: crate::service::config::StoredUser) {
        if self.authentication_busy() || idx >= self.config.users.len() {
            return;
        }
        self.invalidate_user_online_info(idx);
        self.config.users[idx] = user;
        self.ensure_statuses();
        self.user_statuses[idx] = UserStatus::new();
        self.reconnect_targets.retain(|&i| i != idx);
        self.invalidate_auth_context();
    }

    pub fn remove_user(&mut self, idx: usize) -> bool {
        if self.authentication_busy() || idx >= self.config.users.len() {
            return false;
        }
        self.ensure_statuses();
        self.invalidate_user_online_info(idx);
        self.config.users.remove(idx);
        self.user_statuses.remove(idx);
        self.reconnect_targets.retain(|&i| i != idx);
        for target in &mut self.reconnect_targets {
            if *target > idx {
                *target -= 1;
            }
        }
        self.invalidate_auth_context();
        true
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
    fn replacing_an_account_clears_its_session_and_reconnect_target() {
        let mut s = AppState::new(AppConfig::default());
        let user = crate::service::config::StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        };
        s.config.users.push(user.clone());
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.1".into();
        s.online_info = Some(OnlineUserInfo {
            user_name: "test-user".into(),
            error: "ok".into(),
            ..Default::default()
        });
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.reconnect_targets.push(0);
        s.replace_user(0, user);
        assert!(s.online_info.is_none());
        assert_eq!(s.campus_auth, CampusAuthStatus::Unknown);
        assert_eq!(s.user_statuses[0].state, LoginState::LoggedOut);
        assert!(s.user_statuses[0].current_ip.is_empty());
        assert!(s.reconnect_targets.is_empty());
        assert_eq!(s.auth_generation, 1);
    }

    #[test]
    fn changing_server_discards_old_session_state() {
        let mut s = AppState::new(AppConfig::default());
        s.config.users.push(crate::service::config::StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.1".into();
        s.online_info = Some(OnlineUserInfo {
            error: "ok".into(),
            user_name: "test-user".into(),
            ..Default::default()
        });
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.reconnect_targets.push(0);
        s.internet_fail_count = 3;
        assert!(s.set_server("http://other.invalid".into()));
        assert!(s.online_info.is_none());
        assert_eq!(s.campus_auth, CampusAuthStatus::Unknown);
        assert_eq!(s.user_statuses[0].state, LoginState::LoggedOut);
        assert!(s.user_statuses[0].current_ip.is_empty());
        assert!(s.reconnect_targets.is_empty());
        assert_eq!(s.internet_fail_count, 0);
    }

    #[test]
    fn stale_or_inactive_account_is_not_presented_as_confirmed() {
        let mut s = AppState::new(AppConfig::default());
        s.config.users.push(crate::service::config::StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.online_info = Some(OnlineUserInfo {
            error: "ok".into(),
            user_name: "test-user".into(),
            ..Default::default()
        });
        s.campus_auth = CampusAuthStatus::LoggedIn;
        assert!(s.confirmed_user_info(0).is_some());
        s.online_info_stale = true;
        assert!(s.confirmed_user_info(0).is_none());
        assert!(s.current_online_info().is_none());
        s.online_info_stale = false;
        s.user_statuses[0].state = LoginState::LoggedOut;
        assert!(s.confirmed_user_info(0).is_none());
    }

    #[test]
    fn account_mutation_is_blocked_during_authentication() {
        let mut s = AppState::new(AppConfig::default());
        let user = crate::service::config::StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        };
        s.config.users.push(user.clone());
        s.ensure_statuses();
        s.auth_busy = true;
        assert!(!s.remove_user(0));
        s.replace_user(
            0,
            crate::service::config::StoredUser {
                username: "other-test-user".into(),
                ..user.clone()
            },
        );
        assert_eq!(s.config.users[0], user);
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
