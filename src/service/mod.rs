use std::sync::{Arc, Mutex};

use crate::service::config::AppConfig;

pub mod auth;
pub mod config;
pub mod detection;
pub mod monitor;

#[derive(Debug, Clone, PartialEq)]
pub enum LoginState {
    LoggedOut,
    LoggingIn,
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
    pub auth_fail_count: u32,
    pub internet_fail_count: u32,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let user_count = config.users.len();
        Self {
            config,
            user_statuses: vec![UserStatus::new(); user_count],
            log_messages: Vec::new(),
            campus_ip: None,
            auth_server: AuthServerStatus::Unknown,
            campus_auth: CampusAuthStatus::Unknown,
            ipv4_internet: Ipv4InternetStatus::Checking,
            auth_fail_count: 0,
            internet_fail_count: 0,
        }
    }

    pub fn add_log(&mut self, msg: String) {
        self.log_messages.push(msg);
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
