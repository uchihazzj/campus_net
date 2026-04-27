use std::time::Duration;

use crate::service::auth::do_login;
use crate::service::detection::{check_auth_status, check_ipv4_reachability, detect_campus_ip, CampusAuthStatus};
use crate::service::{Ipv4InternetStatus, LoginState, SharedState};

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

            // No campus IPv4 → skip detection and auto-reconnect
            if campus_ipv4.is_none() {
                let mut s = state.lock().unwrap();
                s.campus_auth = CampusAuthStatus::Unknown;
                s.ipv4_internet = Ipv4InternetStatus::Checking;
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }
            let ip = campus_ipv4.as_deref();

            // ── Layer 2: Campus Auth ────────────────────
            let auth_status = check_auth_status(ip).await;
            {
                let mut s = state.lock().unwrap();
                s.campus_auth = auth_status.clone();
            }

            // ── Layer 3: IPv4 Internet ──────────────────
            let ipv4_status = check_ipv4_reachability(ip).await;
            {
                let mut s = state.lock().unwrap();
                if matches!(ipv4_status, Ipv4InternetStatus::Reachable) {
                    s.ipv4_internet = Ipv4InternetStatus::Reachable;
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

            if !auto_reconnect {
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }

            let mut should_reconnect = false;
            let mut log_msg = String::new();

            // Case 1: Campus auth not logged in → re-login
            if auth == CampusAuthStatus::NotLoggedIn && !online_indices.is_empty() {
                let mut s = state.lock().unwrap();
                s.auth_fail_count += 1;
                if s.auth_fail_count >= FAILURE_THRESHOLD {
                    s.auth_fail_count = 0;
                    log_msg = "[WARN] Campus auth lost, reconnecting...".to_string();
                    should_reconnect = true;
                }
            }

            // Case 2: Logged in but IPv4 internet unreachable
            if !should_reconnect
                && auth == CampusAuthStatus::LoggedIn
                && !online_indices.is_empty()
                && matches!(inet, Ipv4InternetStatus::Unreachable)
                && fail_count >= FAILURE_THRESHOLD
            {
                let mut s = state.lock().unwrap();
                s.internet_fail_count = 0;
                log_msg = "[WARN] IPv4 internet lost, reconnecting...".to_string();
                should_reconnect = true;
            }

            if should_reconnect {
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(log_msg);
                }
                for idx in &online_indices {
                    do_login(state.clone(), *idx).await;
                }
                // Check if any came back online
                let success = {
                    let s = state.lock().unwrap();
                    online_indices.iter().any(|&i| {
                        s.user_statuses.get(i).map(|us| us.state == LoginState::Online).unwrap_or(false)
                    })
                };
                // Backoff: double on failure, reset on success
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
