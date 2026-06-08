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
const MONITOR_CRASH_RESTART_SECS: u64 = 30;

/// Decision from the unified auto-reconnect evaluation.
enum ReconnectDecision {
    /// All clear — user logged in, no reconnect needed.
    Healthy,
    /// Uncertain state — do nothing, wait for next cycle.
    Wait,
    /// Definitely offline — auto-reconnect should proceed.
    Reconnect,
}

/// Check whether any user has a usable login IP (current_ip, user.ip, or
/// if_name that resolves). Returns true if at least one source is available.
fn any_usable_ip(s: &crate::service::AppState) -> bool {
    if s.campus_ip.is_some() {
        return true;
    }
    for (i, us) in s.user_statuses.iter().enumerate() {
        if !us.current_ip.is_empty() {
            return true;
        }
        if let Some(user) = s.config.users.get(i) {
            if user.ip.as_ref().is_some_and(|ip| !ip.is_empty()) {
                return true;
            }
            if let Some(ref name) = user.if_name {
                if crate::core::utils::get_ip_by_if_name(name).is_some() {
                    return true;
                }
            }
        }
    }
    false
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
    if !any_usable_ip(s) {
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

/// Run one full monitor iteration. Returns the next backoff_secs value.
/// This is run as a separate tokio task so panics are caught by the outer loop.
async fn run_monitor_iteration(state: &SharedState, interval: u64, backoff_secs: u64) -> u64 {
    // ── Layer 1: Campus IPv4 ────────────────────
    let campus_ipv4 = detect_campus_ip();
    {
        let mut s = state.lock().unwrap();
        s.campus_ip = campus_ipv4.clone();
    }
    crate::service::request_ui_repaint();

    let has_usable_ip = {
        let s = state.lock().unwrap();
        any_usable_ip(&s)
    };

    if campus_ipv4.is_none() && !has_usable_ip {
        let mut s = state.lock().unwrap();
        s.auth_server = AuthServerStatus::Unknown;
        s.campus_auth = CampusAuthStatus::Unknown;
        s.ipv4_internet = if s.config.enable_ipv4_internet_probe {
            Ipv4InternetStatus::Checking
        } else {
            Ipv4InternetStatus::Disabled
        };
        s.internet_fail_count = 0;
        s.add_log(
            "[WARN] No campus IPv4 detected and no user-bound IP available; waiting".to_string(),
        );
        crate::service::request_ui_repaint();
        return interval;
    }

    if campus_ipv4.is_none() {
        let mut s = state.lock().unwrap();
        s.auth_server = AuthServerStatus::Unknown;
        s.add_log(
            "[WARN] No global campus IPv4 detected, but user-bound IP exists; preserving current auth status and continuing auto-reconnect evaluation"
                .to_string(),
        );
        crate::service::request_ui_repaint();
    }
    let ip = campus_ipv4.as_deref();

    // ── Layer 2+3: Auth Server + Auth Status ─────
    sync_online_state(state).await;

    // ── Layer 4: IPv4 Internet (conditional) ─────
    let probe_enabled = {
        let s = state.lock().unwrap();
        s.config.enable_ipv4_internet_probe
    };

    if probe_enabled {
        if let Some(bind_ip) = ip {
            let ipv4_status = check_ipv4_reachability(Some(bind_ip)).await;
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
            crate::service::request_ui_repaint();
        } else {
            let mut s = state.lock().unwrap();
            s.ipv4_internet = Ipv4InternetStatus::ProbeFailed;
            s.add_log(
                "[WARN] IPv4 probe skipped: no global campus IPv4 for bound probe, but user-bound IP exists"
                    .to_string(),
            );
            crate::service::request_ui_repaint();
        }
    } else {
        let mut s = state.lock().unwrap();
        s.ipv4_internet = Ipv4InternetStatus::Disabled;
        crate::service::request_ui_repaint();
    }

    // ── Auto-reconnect ──────────────────────────
    let decision = {
        let s = state.lock().unwrap();
        evaluate_reconnect(&s)
    };

    match decision {
        ReconnectDecision::Healthy => {
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
                crate::service::request_ui_repaint();
            }
            interval
        }

        ReconnectDecision::Wait => interval,

        ReconnectDecision::Reconnect => {
            let (targets, created_targets) = {
                let mut s = state.lock().unwrap();
                let mut created_targets = false;
                if s.reconnect_targets.is_empty() {
                    let online: Vec<usize> = s
                        .user_statuses
                        .iter()
                        .enumerate()
                        .filter(|(_, us)| {
                            us.state == LoginState::Online || us.state == LoginState::PendingConfirm
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if !online.is_empty() {
                        s.reconnect_targets = online;
                    } else {
                        s.reconnect_targets = (0..s.config.users.len()).collect();
                    }
                    let target_count = s.reconnect_targets.len();
                    s.add_log(format!(
                        "[INFO] Auto-reconnect: trying {} user(s)",
                        target_count
                    ));
                    created_targets = true;
                }
                let user_len = s.config.users.len();
                s.reconnect_targets.retain(|&i| i < user_len);
                (s.reconnect_targets.clone(), created_targets)
            };
            if created_targets {
                crate::service::request_ui_repaint();
            }

            if targets.is_empty() {
                return interval;
            }

            let mut any_portal_ok = false;
            for idx in &targets {
                do_login(state.clone(), *idx).await;
                let post_state = {
                    let s = state.lock().unwrap();
                    s.user_statuses
                        .get(*idx)
                        .map(|us| us.state.clone())
                        .unwrap_or(LoginState::Error)
                };
                if post_state == LoginState::PendingConfirm || post_state == LoginState::Online {
                    any_portal_ok = true;
                    break;
                }
            }

            if any_portal_ok {
                let mut s = state.lock().unwrap();
                s.reconnect_targets.clear();
                s.online_info_fail_count = 0;
                s.add_log(
                    "[OK] Auto-reconnect login request succeeded, waiting for server confirmation"
                        .to_string(),
                );
                crate::service::request_ui_repaint();
                interval
            } else {
                let mut s = state.lock().unwrap();
                let next = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                s.add_log(format!(
                    "[WARN] Auto-reconnect failed, will retry in {}s",
                    next
                ));
                crate::service::request_ui_repaint();
                next
            }
        }
    }
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

            // Run each cycle as a separate task so panics are caught.
            // If the cycle panics, the outer loop logs the error and restarts
            // after a delay instead of silently dying.
            let cycle_state = state.clone();
            let handle = tokio::spawn(async move {
                run_monitor_iteration(&cycle_state, interval, backoff_secs).await
            });

            match handle.await {
                Ok(new_backoff) => {
                    backoff_secs = new_backoff;
                }
                Err(e) if e.is_panic() => {
                    tracing::error!(
                        "[Monitor] cycle panicked: {}, restarting in {}s",
                        e,
                        MONITOR_CRASH_RESTART_SECS
                    );
                    if let Ok(mut s) = state.lock() {
                        s.add_log(format!(
                            "[ERROR] Network monitor crashed: {}. Restarting in {}s...",
                            e, MONITOR_CRASH_RESTART_SECS
                        ));
                    }
                    backoff_secs = MONITOR_CRASH_RESTART_SECS;
                }
                Err(_) => {
                    // Task cancelled — shutdown
                    tracing::info!("[Monitor] task cancelled, exiting");
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::config::{AppConfig, StoredUser};
    use crate::service::AppState;

    fn make_state() -> AppState {
        AppState::new(AppConfig::default())
    }

    #[test]
    fn any_ip_with_campus_ip() {
        let mut s = make_state();
        s.campus_ip = Some("10.0.0.1".to_string());
        assert!(any_usable_ip(&s));
    }

    #[test]
    fn any_ip_with_user_ip() {
        let mut s = make_state();
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.2".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        assert!(any_usable_ip(&s));
    }

    #[test]
    fn any_ip_with_if_name() {
        let ifaces = crate::core::utils::get_network_interfaces();
        let real_if_name = ifaces
            .iter()
            .find(|(_, ip)| ip.is_ipv4())
            .map(|(name, _)| name.clone());

        let mut s = make_state();
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: None,
            if_name: real_if_name,
        });
        s.ensure_statuses();
        if s.config.users[0].if_name.is_some() {
            assert!(any_usable_ip(&s));
        }
    }

    #[test]
    fn any_ip_with_current_ip() {
        let mut s = make_state();
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.ensure_statuses();
        s.user_statuses[0].current_ip = "10.0.0.3".to_string();
        assert!(any_usable_ip(&s));
    }

    #[test]
    fn no_ip_at_all() {
        let s = make_state();
        assert!(!any_usable_ip(&s));
    }

    // ── evaluate_reconnect with user-bound IP ─────────────

    #[test]
    fn reconnect_user_ip_without_campus_ip() {
        let mut s = make_state();
        s.config.auto_reconnect = true;
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.2".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        assert!(matches!(
            evaluate_reconnect(&s),
            ReconnectDecision::Reconnect
        ));
    }

    #[test]
    fn reconnect_current_ip_without_campus_ip() {
        let mut s = make_state();
        s.config.auto_reconnect = true;
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.ensure_statuses();
        s.user_statuses[0].current_ip = "10.0.0.3".to_string();
        assert!(matches!(
            evaluate_reconnect(&s),
            ReconnectDecision::Reconnect
        ));
    }

    #[test]
    fn no_reconnect_without_any_ip() {
        let mut s = make_state();
        s.config.auto_reconnect = true;
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        assert!(matches!(evaluate_reconnect(&s), ReconnectDecision::Wait));
    }
}
