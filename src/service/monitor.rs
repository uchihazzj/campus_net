use std::time::Duration;

use crate::service::auth::do_login;
use crate::service::detection::{check_ipv4_reachability, detect_campus_ip};
use crate::service::online_info::sync_online_state;
use crate::service::{
    AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus, LoginState, SharedState,
};

const MIN_INTERVAL_SECS: u64 = 15;
const MAX_INTERVAL_SECS: u64 = 300;
const MAX_BACKOFF_SECS: u64 = 300;
const FAILURE_THRESHOLD: u32 = 2;

pub fn spawn_monitor(state: SharedState) {
    tokio::spawn(async move {
        let initial_interval = {
            let mut s = state.lock().unwrap();
            let iv = s
                .config
                .monitor_interval_secs
                .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS);
            s.add_log(format!("[INFO] Network monitor interval: {}s", iv));
            iv
        };
        let mut backoff_secs = initial_interval;

        loop {
            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;

            let interval = {
                let s = state.lock().unwrap();
                s.config
                    .monitor_interval_secs
                    .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS)
            };

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
                s.ipv4_internet = if s.config.enable_ipv4_internet_probe {
                    Ipv4InternetStatus::Checking
                } else {
                    Ipv4InternetStatus::Disabled
                };
                s.internet_fail_count = 0;
                s.reconnect_targets.clear();
                backoff_secs = interval;
                continue;
            }
            let ip = campus_ipv4.as_deref();

            // ── Layer 2+3: Auth Server + Auth Status ─────
            // Merged into a single rad_user_info query that provides both
            // server reachability AND definitive login state (+ account identity).
            sync_online_state(&state).await;

            // ── Layer 4: IPv4 Internet (conditional) ─────
            let probe_enabled = {
                let s = state.lock().unwrap();
                s.config.enable_ipv4_internet_probe
            };

            if probe_enabled {
                let ipv4_status = check_ipv4_reachability(ip).await;
                {
                    let mut s = state.lock().unwrap();
                    match &ipv4_status {
                        Ipv4InternetStatus::Reachable => {
                            s.internet_fail_count = 0;
                            s.ipv4_internet = Ipv4InternetStatus::Reachable;
                            if !s.reconnect_targets.is_empty() {
                                s.add_log(
                                    "[INFO] IPv4 internet restored, clearing reconnect targets"
                                        .to_string(),
                                );
                                s.reconnect_targets.clear();
                            }
                        }
                        Ipv4InternetStatus::CaptivePortal => {
                            s.internet_fail_count += 1;
                            if s.internet_fail_count >= FAILURE_THRESHOLD {
                                s.ipv4_internet = Ipv4InternetStatus::CaptivePortal;
                            }
                        }
                        _ => {
                            s.internet_fail_count += 1;
                            if s.internet_fail_count >= FAILURE_THRESHOLD {
                                s.ipv4_internet = ipv4_status.clone();
                            }
                        }
                    }
                }
            } else {
                let mut s = state.lock().unwrap();
                s.ipv4_internet = Ipv4InternetStatus::Disabled;
            }

            // ── Auto-reconnect ──────────────────────────
            let (auto_reconnect, inet, fail_count, auth, online_info_fail_count, online_info) = {
                let s = state.lock().unwrap();
                (
                    s.config.auto_reconnect,
                    s.ipv4_internet.clone(),
                    s.internet_fail_count,
                    s.campus_auth.clone(),
                    s.online_info_fail_count,
                    s.online_info.clone(),
                )
            };

            if !auto_reconnect {
                backoff_secs = interval;
                continue;
            }

            // If online_info is definitive (fail_count == 0), use it as the
            // primary signal. Only fall back to captive portal detection when
            // rad_user_info has been failing for >= 3 cycles.
            let degraded = online_info_fail_count >= 3;
            let inet_disabled = matches!(inet, Ipv4InternetStatus::Disabled);

            // Determine if we're in trouble
            let trouble = if degraded {
                // Fallback: use existing captive portal / unreachable detection
                // (only meaningful when probe is enabled)
                if inet_disabled {
                    auth == CampusAuthStatus::NotLoggedIn
                } else {
                    matches!(inet, Ipv4InternetStatus::CaptivePortal)
                        || matches!(inet, Ipv4InternetStatus::Unreachable)
                        || matches!(inet, Ipv4InternetStatus::ProbeFailed)
                        || auth == CampusAuthStatus::NotLoggedIn
                }
            } else if online_info.is_some() {
                // Server confirms logged in — no reconnect needed.
                // IPv4 unreachable when probe is enabled is a routing issue,
                // not an auth failure.
                if !inet_disabled
                    && matches!(inet, Ipv4InternetStatus::Unreachable)
                    && fail_count >= FAILURE_THRESHOLD
                {
                    // Log as warning but don't trigger reconnect
                    let mut s = state.lock().unwrap();
                    s.add_log(
                        "[WARN] Online but IPv4 unreachable — possible routing issue, not reconnecting"
                            .to_string(),
                    );
                }
                false
            } else {
                // online_info is None (not logged in) or transitioning
                if inet_disabled {
                    auth == CampusAuthStatus::NotLoggedIn
                } else {
                    auth == CampusAuthStatus::NotLoggedIn
                        || matches!(inet, Ipv4InternetStatus::CaptivePortal)
                        || (matches!(inet, Ipv4InternetStatus::Unreachable)
                            && fail_count >= FAILURE_THRESHOLD)
                }
            };

            if !trouble {
                // All clear — clear reconnect targets
                {
                    let mut s = state.lock().unwrap();
                    if !s.reconnect_targets.is_empty() {
                        s.add_log("[INFO] Network healthy, clearing reconnect targets".to_string());
                        s.reconnect_targets.clear();
                    }
                }
                backoff_secs = interval;
                continue;
            }

            // Snapshot online users as reconnect targets.
            // Only populate when targets are empty (first trouble detection).
            {
                let mut s = state.lock().unwrap();
                if s.reconnect_targets.is_empty() {
                    let targets: Vec<usize> = s
                        .user_statuses
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

            let (targets, target_count) = {
                let mut s = state.lock().unwrap();
                let user_len = s.config.users.len();
                s.reconnect_targets.retain(|&i| i < user_len);
                (s.reconnect_targets.clone(), user_len)
            };

            if targets.is_empty() {
                // Check if we should fall back to reconnecting all configured users
                let should_reconnect_all = {
                    let s = state.lock().unwrap();
                    s.reconnect_targets.is_empty()
                        && trouble
                        && target_count > 0
                        && s.user_statuses.iter().all(|us| {
                            us.state == LoginState::LoggedOut || us.state == LoginState::Error
                        })
                };

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
                    let mut any_success = false;
                    for idx in &all_indices {
                        do_login(state.clone(), *idx).await;
                        let success = {
                            let s = state.lock().unwrap();
                            s.user_statuses
                                .get(*idx)
                                .map(|us| us.state == LoginState::Online)
                                .unwrap_or(false)
                        };
                        if success {
                            any_success = true;
                            break;
                        }
                    }
                    if any_success {
                        let mut s = state.lock().unwrap();
                        s.reconnect_targets.clear();
                        s.add_log("[OK] Auto-reconnect succeeded".to_string());
                        backoff_secs = interval;
                    } else {
                        let mut s = state.lock().unwrap();
                        s.add_log(format!(
                            "[WARN] Auto-reconnect failed, will retry in {}s",
                            (backoff_secs * 2).min(MAX_BACKOFF_SECS)
                        ));
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    }
                    continue;
                }
                backoff_secs = interval;
                continue;
            }

            let mut should_reconnect = false;
            let mut log_msg = String::new();

            // Use online_info as the primary decision signal when available
            if !degraded && online_info.is_some() {
                // Server confirms logged in — only reconnect if IPv4 is truly unreachable
                if matches!(inet, Ipv4InternetStatus::Unreachable)
                    && fail_count >= FAILURE_THRESHOLD
                {
                    let mut s = state.lock().unwrap();
                    s.internet_fail_count = 0;
                    log_msg = format!(
                        "[WARN] Online but IPv4 unreachable (fail_count={}), reconnecting {} user(s)...",
                        fail_count,
                        targets.len()
                    );
                    should_reconnect = true;
                }
            } else if !degraded {
                // online_info is None → server says not logged in
                let mut s = state.lock().unwrap();
                s.auth_fail_count += 1;
                if s.auth_fail_count >= FAILURE_THRESHOLD {
                    s.auth_fail_count = 0;
                    log_msg = format!(
                        "[WARN] Server confirmed not logged in, reconnecting {} user(s)...",
                        targets.len()
                    );
                    should_reconnect = true;
                }
            } else {
                // Degraded: use original captive portal logic
                if matches!(inet, Ipv4InternetStatus::CaptivePortal)
                    && fail_count >= FAILURE_THRESHOLD
                {
                    let mut s = state.lock().unwrap();
                    s.internet_fail_count = 0;
                    log_msg = format!(
                        "[WARN] IPv4 captive portal detected (degraded, fail_count={}), reconnecting {} user(s)...",
                        fail_count,
                        targets.len()
                    );
                    should_reconnect = true;
                } else if auth == CampusAuthStatus::NotLoggedIn {
                    let mut s = state.lock().unwrap();
                    s.auth_fail_count += 1;
                    if s.auth_fail_count >= FAILURE_THRESHOLD {
                        s.auth_fail_count = 0;
                        log_msg = format!(
                            "[WARN] Campus auth lost (degraded, NotLoggedIn), reconnecting {} user(s)...",
                            targets.len()
                        );
                        should_reconnect = true;
                    }
                } else if auth == CampusAuthStatus::LoggedIn
                    && matches!(inet, Ipv4InternetStatus::Unreachable)
                    && fail_count >= FAILURE_THRESHOLD
                {
                    let mut s = state.lock().unwrap();
                    s.internet_fail_count = 0;
                    log_msg = format!(
                        "[WARN] IPv4 internet unreachable (degraded, fail_count={}), reconnecting {} user(s)...",
                        fail_count,
                        targets.len()
                    );
                    should_reconnect = true;
                }
            }

            if should_reconnect {
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(log_msg);
                }
                let mut any_success = false;
                for idx in &targets {
                    do_login(state.clone(), *idx).await;
                    let success = {
                        let s = state.lock().unwrap();
                        s.user_statuses
                            .get(*idx)
                            .map(|us| us.state == LoginState::Online)
                            .unwrap_or(false)
                    };
                    if success {
                        any_success = true;
                        break;
                    }
                }
                if any_success {
                    let mut s = state.lock().unwrap();
                    s.reconnect_targets.clear();
                    s.add_log("[OK] Auto-reconnect succeeded".to_string());
                    backoff_secs = interval;
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
                if (matches!(inet, Ipv4InternetStatus::CaptivePortal)
                    || matches!(inet, Ipv4InternetStatus::Unreachable))
                    && fail_count < FAILURE_THRESHOLD
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                            "[INFO] Trouble detected (inet={:?}) but fail_count={}/{} — waiting for next cycle",
                            inet, fail_count, FAILURE_THRESHOLD
                        ));
                }
                backoff_secs = interval;
            }
        }
    });
}
