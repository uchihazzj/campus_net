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
                s.internet_fail_count = 0;
                s.reconnect_targets.clear();
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
                match &ipv4_status {
                    Ipv4InternetStatus::Reachable => {
                        s.internet_fail_count = 0;
                        s.ipv4_internet = Ipv4InternetStatus::Reachable;
                        if !s.reconnect_targets.is_empty() {
                            s.add_log("[INFO] IPv4 internet restored, clearing reconnect targets".to_string());
                            s.reconnect_targets.clear();
                        }
                    }
                    // CaptivePortal means IPv4 is hijacked by the auth portal —
                    // NOT a success state. Count failures and trigger reconnect.
                    Ipv4InternetStatus::CaptivePortal => {
                        s.internet_fail_count += 1;
                        if s.internet_fail_count >= FAILURE_THRESHOLD {
                            s.ipv4_internet = Ipv4InternetStatus::CaptivePortal;
                        }
                    }
                    // Unreachable / ProbeFailed
                    _ => {
                        s.internet_fail_count += 1;
                        if s.internet_fail_count >= FAILURE_THRESHOLD {
                            s.ipv4_internet = ipv4_status.clone();
                        }
                    }
                }
            }

            // ── Auto-reconnect ──────────────────────────
            let (auto_reconnect, inet, fail_count, auth) = {
                let s = state.lock().unwrap();
                (
                    s.config.auto_reconnect,
                    s.ipv4_internet.clone(),
                    s.internet_fail_count,
                    s.campus_auth.clone(),
                )
            };

            if !auto_reconnect {
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }

            // Snapshot online users as reconnect targets.
            // Only populate when targets are empty (first trouble detection).
            {
                let mut s = state.lock().unwrap();
                if s.reconnect_targets.is_empty() {
                    let trouble = matches!(inet, Ipv4InternetStatus::CaptivePortal)
                        || matches!(inet, Ipv4InternetStatus::Unreachable)
                        || matches!(inet, Ipv4InternetStatus::ProbeFailed)
                        || auth == CampusAuthStatus::NotLoggedIn;
                    if trouble {
                        let targets: Vec<usize> = s.user_statuses
                            .iter()
                            .enumerate()
                            .filter(|(_, us)| us.state == LoginState::Online)
                            .map(|(i, _)| i)
                            .collect();
                        if !targets.is_empty() {
                            s.reconnect_targets = targets;
                        }
                    }
                }
            }

            let (targets, target_count) = {
                let s = state.lock().unwrap();
                (s.reconnect_targets.clone(), s.config.users.len())
            };

            if targets.is_empty() {
                // Check if we should fall back to reconnecting all configured users
                let should_reconnect_all = {
                    let s = state.lock().unwrap();
                    s.reconnect_targets.is_empty()
                        && (matches!(inet, Ipv4InternetStatus::CaptivePortal)
                            || matches!(inet, Ipv4InternetStatus::Unreachable)
                            || auth == CampusAuthStatus::NotLoggedIn)
                        && target_count > 0
                        && s.user_statuses.iter().all(|us| {
                            us.state == LoginState::LoggedOut || us.state == LoginState::Error
                        })
                }; // MutexGuard dropped here

                if should_reconnect_all {
                    let all_indices: Vec<usize> = (0..target_count).collect();
                    {
                        let mut s = state.lock().unwrap();
                        s.reconnect_targets = all_indices.clone();
                        s.add_log(format!(
                            "[INFO] No online users found, will reconnect all {} configured user(s)",
                            all_indices.len()
                        ));
                    }
                    for idx in &all_indices {
                        do_login(state.clone(), *idx).await;
                    }
                }
                backoff_secs = BASE_INTERVAL_SECS;
                continue;
            }

            let mut should_reconnect = false;
            let mut log_msg = String::new();

            // Case 1: CaptivePortal detected → IPv4 hijacked by portal, need re-login
            if matches!(inet, Ipv4InternetStatus::CaptivePortal) && fail_count >= FAILURE_THRESHOLD {
                let mut s = state.lock().unwrap();
                s.internet_fail_count = 0;
                log_msg = format!(
                    "[WARN] IPv4 captive portal detected (fail_count={}), reconnecting {} user(s)...",
                    fail_count,
                    targets.len()
                );
                should_reconnect = true;
            }
            // Case 2: Campus auth is NotLoggedIn
            else if auth == CampusAuthStatus::NotLoggedIn {
                let mut s = state.lock().unwrap();
                s.auth_fail_count += 1;
                if s.auth_fail_count >= FAILURE_THRESHOLD {
                    s.auth_fail_count = 0;
                    log_msg = format!(
                        "[WARN] Campus auth lost (NotLoggedIn), reconnecting {} user(s)...",
                        targets.len()
                    );
                    should_reconnect = true;
                }
            }
            // Case 3: LoggedIn but IPv4 unreachable
            else if auth == CampusAuthStatus::LoggedIn
                && matches!(inet, Ipv4InternetStatus::Unreachable)
                && fail_count >= FAILURE_THRESHOLD
            {
                let mut s = state.lock().unwrap();
                s.internet_fail_count = 0;
                log_msg = format!(
                    "[WARN] IPv4 internet unreachable (fail_count={}), reconnecting {} user(s)...",
                    fail_count,
                    targets.len()
                );
                should_reconnect = true;
            }

            if should_reconnect {
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(log_msg);
                }
                for idx in &targets {
                    do_login(state.clone(), *idx).await;
                }
                let success = {
                    let s = state.lock().unwrap();
                    targets.iter().any(|&i| {
                        s.user_statuses
                            .get(i)
                            .map(|us| us.state == LoginState::Online)
                            .unwrap_or(false)
                    })
                };
                if success {
                    let mut s = state.lock().unwrap();
                    s.reconnect_targets.clear();
                    s.add_log("[OK] Auto-reconnect succeeded".to_string());
                    backoff_secs = BASE_INTERVAL_SECS;
                } else {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                        "[WARN] Auto-reconnect failed, will retry in {}s",
                        (backoff_secs * 2).min(MAX_BACKOFF_SECS)
                    ));
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                }
            } else {
                // Log why we're NOT reconnecting
                if matches!(inet, Ipv4InternetStatus::CaptivePortal) || matches!(inet, Ipv4InternetStatus::Unreachable) {
                    if fail_count < FAILURE_THRESHOLD {
                        let mut s = state.lock().unwrap();
                        s.add_log(format!(
                            "[INFO] Trouble detected (inet={:?}) but fail_count={}/{} — waiting for next cycle",
                            inet, fail_count, FAILURE_THRESHOLD
                        ));
                    }
                }
                backoff_secs = BASE_INTERVAL_SECS;
            }
        }
    });
}
