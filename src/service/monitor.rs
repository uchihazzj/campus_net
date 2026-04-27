use std::time::Duration;

use crate::service::auth::do_login;
use crate::service::detection::{
    check_auth_status, check_internet_reachability, detect_campus_ip, CampusAuthStatus,
    ReachabilityResult,
};
use crate::service::{InternetStatus, LoginState, SharedState};

const CHECK_INTERVAL_SECS: u64 = 15;
const FAILURE_THRESHOLD: u32 = 3;

pub fn spawn_monitor(state: SharedState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(CHECK_INTERVAL_SECS)).await;

            // ── Layer 1: Campus IP ───────────────────────
            let campus_ip = detect_campus_ip();
            {
                let mut s = state.lock().unwrap();
                s.campus_ip = campus_ip;
            }

            // ── Layer 2: Campus Auth ─────────────────────
            let auth_status = check_auth_status().await;
            {
                let mut s = state.lock().unwrap();
                s.campus_auth = auth_status.clone();
            }

            // ── Layer 3: Internet Reachability ───────────
            let reachability = check_internet_reachability().await;

            // Update internet status with consecutive-failure tracking
            let internet_state = match &reachability {
                ReachabilityResult::Reachable => InternetStatus::Online,
                ReachabilityResult::CaptivePortal => InternetStatus::CaptivePortal,
                ReachabilityResult::Unreachable => InternetStatus::Offline,
            };
            {
                let mut s = state.lock().unwrap();
                if matches!(internet_state, InternetStatus::Online) {
                    s.internet_fail_count = 0;
                } else {
                    s.internet_fail_count += 1;
                }
                // Only show offline after consecutive failures
                if s.internet_fail_count >= FAILURE_THRESHOLD
                    || matches!(internet_state, InternetStatus::Online)
                {
                    s.internet_status = internet_state;
                }
            }

            // ── Auto-reconnect logic ─────────────────────
            let (auto_reconnect, online_indices, auth, internet) = {
                let s = state.lock().unwrap();
                let auto = s.config.auto_reconnect;
                let indices: Vec<usize> = s
                    .user_statuses
                    .iter()
                    .enumerate()
                    .filter(|(_, us)| us.state == LoginState::Online)
                    .map(|(i, _)| i)
                    .collect();
                let auth = s.campus_auth.clone();
                let inet = s.internet_status.clone();
                (auto, indices, auth, inet)
            };

            if !auto_reconnect {
                continue;
            }

            // Case 1: Logged in users but campus auth shows NotLoggedIn → re-login
            if auth == CampusAuthStatus::NotLoggedIn && !online_indices.is_empty() {
                let should_reconnect = {
                    let mut s = state.lock().unwrap();
                    s.auth_fail_count += 1;
                    if s.auth_fail_count < FAILURE_THRESHOLD {
                        false
                    } else {
                        s.auth_fail_count = 0;
                        s.add_log("[WARN] Campus auth lost, reconnecting...".to_string());
                        true
                    }
                }; // MutexGuard dropped here

                if should_reconnect {
                    for idx in &online_indices {
                        do_login(state.clone(), *idx).await;
                    }
                }
                continue;
            }

            // Reset auth fail count when logged in
            if auth == CampusAuthStatus::LoggedIn {
                let mut s = state.lock().unwrap();
                s.auth_fail_count = 0;
            }

            // Case 2: Logged in but internet unreachable after consecutive failures
            if online_indices.is_empty() {
                continue;
            }
            if !matches!(internet, InternetStatus::Offline) {
                continue;
            }

            let do_reconnect = {
                let s = state.lock().unwrap();
                s.internet_fail_count >= FAILURE_THRESHOLD
            };
            if !do_reconnect {
                continue;
            }

            {
                let mut s = state.lock().unwrap();
                s.add_log("[WARN] Internet lost, reconnecting...".to_string());
            } // MutexGuard dropped here

            for idx in &online_indices {
                do_login(state.clone(), *idx).await;
            }
        }
    });
}
