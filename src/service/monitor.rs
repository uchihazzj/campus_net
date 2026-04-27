use std::time::Duration;

use crate::service::auth::do_login;
use crate::service::detection::{
    check_auth_server, check_auth_status, check_ipv4_reachability, detect_campus_ip,
};
use crate::service::{AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus, LoginState, SharedState};

const BASE_INTERVAL_SECS: u64 = 15;
const MAX_BACKOFF_SECS: u64 = 300;
const FAILURE_THRESHOLD: u32 = 2;

pub fn spawn_monitor(state: SharedState) {
    tokio::spawn(async move {
        let mut backoff_secs = BASE_INTERVAL_SECS;

        loop {
            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;

            // ── Layer 1: Campus IPv4 ────────────────────
            let campus_ipv4 = detect_campus_ip();
            {
                let mut s = state.lock().unwrap();
                s.campus_ip = campus_ipv4.clone();
            }

            if campus_ipv4.is_none() {
                let mut s = state.lock().unwrap();
                s.auth_server = AuthServerStatus::Unknown;
                s.campus_auth = CampusAuthStatus::Unknown;
                s.ipv4_internet = Ipv4InternetStatus::Checking;
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }
            let ip = campus_ipv4.as_deref();

            // ── Layer 2: Auth Server Reachability ───────
            let server = {
                let s = state.lock().unwrap();
                s.config.server.clone()
            };
            let auth_server = check_auth_server(&server, ip).await;
            {
                let mut s = state.lock().unwrap();
                if s.auth_server != auth_server {
                    s.add_log(format!(
                        "[INFO] Auth server {}: {:?}",
                        server, auth_server
                    ));
                }
                s.auth_server = auth_server;
            }

            // ── Layer 3: Captive Portal Probe (Auth Status)
            let auth_status = check_auth_status(ip).await;
            {
                let mut s = state.lock().unwrap();
                s.campus_auth = auth_status.clone();
            }

            // ── Layer 4: IPv4 Internet ──────────────────
            let ipv4_status = check_ipv4_reachability(ip).await;
            {
                let mut s = state.lock().unwrap();
                if matches!(ipv4_status, Ipv4InternetStatus::Reachable) {
                    s.internet_fail_count = 0;
                    s.ipv4_internet = Ipv4InternetStatus::Reachable;
                } else if matches!(ipv4_status, Ipv4InternetStatus::CaptivePortal) {
                    s.internet_fail_count = 0;
                    s.ipv4_internet = Ipv4InternetStatus::CaptivePortal;
                } else {
                    s.internet_fail_count += 1;
                    if s.internet_fail_count >= FAILURE_THRESHOLD {
                        s.ipv4_internet = ipv4_status.clone();
                    }
                }
            }

            // ── Auto-reconnect ──────────────────────────
            let (auto_reconnect, online_indices, auth, inet, fail_count) = {
                let s = state.lock().unwrap();
                (
                    s.config.auto_reconnect,
                    s.user_statuses
                        .iter()
                        .enumerate()
                        .filter(|(_, us)| us.state == LoginState::Online)
                        .map(|(i, _)| i)
                        .collect::<Vec<usize>>(),
                    s.campus_auth.clone(),
                    s.ipv4_internet.clone(),
                    s.internet_fail_count,
                )
            };

            if !auto_reconnect || online_indices.is_empty() {
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }

            let mut should_reconnect = false;
            let mut log_msg = String::new();

            // Only reconnect when auth status is definitively NotLoggedIn
            if auth == CampusAuthStatus::NotLoggedIn {
                let mut s = state.lock().unwrap();
                s.auth_fail_count += 1;
                if s.auth_fail_count >= FAILURE_THRESHOLD {
                    s.auth_fail_count = 0;
                    log_msg = "[WARN] Campus auth lost (NotLoggedIn), reconnecting...".to_string();
                    should_reconnect = true;
                }
            } else if auth == CampusAuthStatus::LoggedIn
                && matches!(inet, Ipv4InternetStatus::Unreachable)
                && fail_count >= FAILURE_THRESHOLD
            {
                let mut s = state.lock().unwrap();
                s.internet_fail_count = 0;
                log_msg = "[WARN] IPv4 internet unreachable despite LoggedIn, reconnecting...".to_string();
                should_reconnect = true;
            }

            // Do NOT reconnect when auth is Unknown — we can't determine state.
            // Wait for the next detection cycle.

            if should_reconnect {
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(log_msg);
                }
                for idx in &online_indices {
                    do_login(state.clone(), *idx).await;
                }
                let success = {
                    let s = state.lock().unwrap();
                    online_indices.iter().any(|&i| {
                        s.user_statuses
                            .get(i)
                            .map(|us| us.state == LoginState::Online)
                            .unwrap_or(false)
                    })
                };
                if success {
                    backoff_secs = BASE_INTERVAL_SECS;
                } else {
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                }
            } else {
                backoff_secs = BASE_INTERVAL_SECS;
            }
        }
    });
}
