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

/// Decision from the unified auto-reconnect evaluation.
enum ReconnectDecision {
    /// All clear — user logged in, no reconnect needed.
    Healthy,
    /// Uncertain state — do nothing, wait for next cycle.
    Wait,
    /// Definitely offline — auto-reconnect should proceed.
    Reconnect,
}

/// Evaluate whether auto-reconnect should fire based on current state.
///
/// - rad_user_info (when working) is authoritative: LoggedIn → Healthy,
///   NotLoggedIn → Reconnect.
/// - When rad_user_info is failing but not yet degraded (1-2 failures),
///   preserve the last known state and wait.
/// - When degraded (≥3 failures), fall back to captive portal / IPv4 probe.
/// - Respects `auto_reconnect` config flag and `suppress_auto_reconnect`
///   (set on manual logout, cleared on manual login).
fn evaluate_reconnect(s: &crate::service::AppState) -> ReconnectDecision {
    if !s.config.auto_reconnect {
        return ReconnectDecision::Wait;
    }
    if s.suppress_auto_reconnect {
        return ReconnectDecision::Wait;
    }
    if s.campus_ip.is_none() {
        return ReconnectDecision::Wait;
    }

    // rad_user_info is authoritative
    if s.online_info_fail_count == 0 {
        match s.campus_auth {
            CampusAuthStatus::LoggedIn => return ReconnectDecision::Healthy,
            CampusAuthStatus::NotLoggedIn => return ReconnectDecision::Reconnect,
            CampusAuthStatus::Unknown => return ReconnectDecision::Wait,
        }
    }

    // rad_user_info failing but not yet degraded — wait
    if s.online_info_fail_count < 3 {
        return ReconnectDecision::Wait;
    }

    // Degraded: use fallback (captive portal / IPv4 probe)
    if s.campus_auth == CampusAuthStatus::NotLoggedIn {
        return ReconnectDecision::Reconnect;
    }
    if s.config.enable_ipv4_internet_probe
        && matches!(s.ipv4_internet, Ipv4InternetStatus::CaptivePortal)
    {
        return ReconnectDecision::Reconnect;
    }

    ReconnectDecision::Wait
}

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
            let decision = {
                let s = state.lock().unwrap();
                evaluate_reconnect(&s)
            };

            match decision {
                ReconnectDecision::Healthy => {
                    // Log IPv4 unreachable warning when online but IPv4 is down
                    let (has_online, probe_enabled, inet, fc) = {
                        let s = state.lock().unwrap();
                        (
                            s.online_info.is_some(),
                            s.config.enable_ipv4_internet_probe,
                            s.ipv4_internet.clone(),
                            s.internet_fail_count,
                        )
                    };
                    if has_online
                        && probe_enabled
                        && matches!(inet, Ipv4InternetStatus::Unreachable)
                        && fc >= FAILURE_THRESHOLD
                    {
                        let mut s = state.lock().unwrap();
                        s.add_log(
                            "[WARN] Online but IPv4 unreachable — possible routing issue, not reconnecting"
                                .to_string(),
                        );
                    }
                    let mut s = state.lock().unwrap();
                    if !s.reconnect_targets.is_empty() {
                        s.reconnect_targets.clear();
                    }
                    backoff_secs = interval;
                }

                ReconnectDecision::Wait => {
                    backoff_secs = interval;
                }

                ReconnectDecision::Reconnect => {
                    // Populate targets if empty
                    let targets = {
                        let mut s = state.lock().unwrap();
                        if s.reconnect_targets.is_empty() {
                            // Prefer users currently showing as Online
                            let online: Vec<usize> = s
                                .user_statuses
                                .iter()
                                .enumerate()
                                .filter(|(_, us)| us.state == LoginState::Online)
                                .map(|(i, _)| i)
                                .collect();
                            if !online.is_empty() {
                                s.reconnect_targets = online;
                            } else {
                                // No previously-online users — try all configured
                                s.reconnect_targets = (0..s.config.users.len()).collect();
                            }
                            let target_count = s.reconnect_targets.len();
                            s.add_log(format!(
                                "[INFO] Auto-reconnect: trying {} user(s)",
                                target_count
                            ));
                        }
                        let user_len = s.config.users.len();
                        s.reconnect_targets.retain(|&i| i < user_len);
                        s.reconnect_targets.clone()
                    };

                    if targets.is_empty() {
                        backoff_secs = interval;
                        continue;
                    }

                    // Try each target in order, stop on first success
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
                        s.online_info_fail_count = 0;
                        s.online_info_stale = false;
                        s.add_log("[OK] Auto-reconnect succeeded".to_string());
                        backoff_secs = interval;
                    } else {
                        let mut s = state.lock().unwrap();
                        let next = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                        s.add_log(format!(
                            "[WARN] Auto-reconnect failed, will retry in {}s",
                            next
                        ));
                        backoff_secs = next;
                    }
                }
            }
        }
    });
}
