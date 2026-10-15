use std::time::Duration;

use crate::service::auth::do_auto_login;
use crate::service::config::StoredUser;
use crate::service::detection::{check_ipv4_reachability, detect_campus_ip_from_interfaces};
use crate::service::online_info::sync_online_state_from_interfaces;
use crate::service::user_ip;
use crate::service::{
    AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus, LoginState, SharedState, UserStatus,
};

const MIN_INTERVAL_SECS: u64 = 15;
const MAX_INTERVAL_SECS: u64 = 300;
const MAX_BACKOFF_SECS: u64 = 300;
const FAILURE_THRESHOLD: u32 = 2;
const MONITOR_CRASH_RESTART_SECS: u64 = 30;

fn cached_online_interfaces(
    s: &crate::service::AppState,
) -> Option<Vec<(String, std::net::IpAddr)>> {
    s.current_online_info()?;
    let interfaces = s.network_interfaces.as_ref()?;
    interfaces
        .iter()
        .any(|(_, ip)| ip.is_ipv4())
        .then(|| interfaces.clone())
}

/// Decision from the unified auto-reconnect evaluation.
enum ReconnectDecision {
    /// All clear — user logged in, no reconnect needed.
    Healthy,
    /// Uncertain state — do nothing, wait for next cycle.
    Wait,
    /// Definitely offline — auto-reconnect should proceed.
    Reconnect,
}

pub(crate) fn reconnect_needed(s: &crate::service::AppState, has_usable_ip: bool) -> bool {
    matches!(
        evaluate_reconnect(s, has_usable_ip),
        ReconnectDecision::Reconnect
    )
}

/// Check whether any user has a usable login IP (current_ip, user.ip, or
/// if_name that resolves). Returns true if at least one source is available.
#[cfg(test)]
fn any_usable_ip(s: &crate::service::AppState) -> bool {
    if s.campus_ip.is_some() {
        return true;
    }
    let users = s.config.users.clone();
    let statuses = s.user_statuses.clone();
    any_usable_user_ip(&users, &statuses, &[])
}

fn any_usable_user_ip(
    users: &[StoredUser],
    statuses: &[UserStatus],
    interfaces: &[(String, std::net::IpAddr)],
) -> bool {
    statuses
        .iter()
        .enumerate()
        .any(|(i, us)| user_ip::has_usable_user_ip(users.get(i), Some(us), interfaces))
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
fn evaluate_reconnect(s: &crate::service::AppState, has_usable_ip: bool) -> ReconnectDecision {
    if !s.config.auto_reconnect {
        return ReconnectDecision::Wait;
    }
    if s.suppress_auto_reconnect {
        return ReconnectDecision::Wait;
    }
    if s.authentication_busy() || s.online_query_busy {
        return ReconnectDecision::Wait;
    }
    if s.campus_ip.is_none() && !has_usable_ip {
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
    if s.definitely_offline() {
        return ReconnectDecision::Reconnect;
    }

    ReconnectDecision::Wait
}

fn ipv4_probe_ip(
    s: &crate::service::AppState,
    interfaces: &[(String, std::net::IpAddr)],
) -> Option<String> {
    // Preserve the existing skip when no global campus IPv4 was detected.
    // Otherwise diagnose the account's actual adapter, as rad_user_info does.
    s.campus_ip.as_ref()?;
    crate::service::online_info::status_query_ip_from_interfaces(s, interfaces)
}

fn apply_ipv4_probe(
    s: &mut crate::service::AppState,
    status: Ipv4InternetStatus,
    auth_generation: u64,
    query_generation: u64,
    ip: &Option<String>,
) -> bool {
    if !s.config.enable_ipv4_internet_probe
        || s.authentication_busy()
        || s.online_query_busy
        || s.auth_generation != auth_generation
        || s.online_query_generation != query_generation
        || &s.campus_ip != ip
    {
        return false;
    }
    match status {
        Ipv4InternetStatus::Reachable => {
            s.internet_fail_count = 0;
            s.ipv4_internet = Ipv4InternetStatus::Reachable;
            // TUN/proxy connectivity does not confirm campus authentication.
            // Only the authoritative Healthy branch may clear reconnect targets.
        }
        _ => {
            s.internet_fail_count = s.internet_fail_count.saturating_add(1);
            if s.internet_fail_count >= FAILURE_THRESHOLD {
                s.ipv4_internet = status;
            }
        }
    }
    true
}

/// Run one full monitor iteration. Returns the next backoff_secs value.
/// This is run as a separate tokio task so panics are caught by the outer loop.
async fn run_monitor_iteration(state: &SharedState, interval: u64, backoff_secs: u64) -> u64 {
    // ── Layer 1: Campus IPv4 ────────────────────
    let (auth_generation, initial_query_generation, cached_interfaces) = {
        let s = state.lock().unwrap();
        if s.authentication_busy() || s.online_query_busy {
            return interval;
        }
        (
            s.auth_generation,
            s.online_query_generation,
            cached_online_interfaces(&s),
        )
    };
    let from_cache = cached_interfaces.is_some();
    let interfaces = if let Some(interfaces) = cached_interfaces {
        interfaces
    } else {
        crate::core::utils::get_network_interfaces_async().await
    };
    let campus_ipv4 = detect_campus_ip_from_interfaces(&interfaces);
    {
        let mut s = state.lock().unwrap();
        if s.authentication_busy()
            || s.online_query_busy
            || s.auth_generation != auth_generation
            || s.online_query_generation != initial_query_generation
        {
            return interval;
        }
        s.campus_ip = campus_ipv4.clone();
    }
    crate::service::request_ui_repaint();

    let has_usable_ip = {
        let s = state.lock().unwrap();
        let users = s.config.users.clone();
        let statuses = s.user_statuses.clone();
        drop(s);
        any_usable_user_ip(&users, &statuses, &interfaces)
    };

    if campus_ipv4.is_none() && !has_usable_ip {
        let mut s = state.lock().unwrap();
        if s.authentication_busy()
            || s.online_query_busy
            || s.auth_generation != auth_generation
            || s.online_query_generation != initial_query_generation
        {
            return interval;
        }
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
        drop(s);
        crate::service::request_ui_repaint();
        return interval;
    }

    if campus_ipv4.is_none() {
        let mut s = state.lock().unwrap();
        if s.authentication_busy()
            || s.online_query_busy
            || s.auth_generation != auth_generation
            || s.online_query_generation != initial_query_generation
        {
            return interval;
        }
        s.auth_server = AuthServerStatus::Unknown;
        s.add_log(
            "[WARN] No global campus IPv4 detected, but user-bound IP exists; preserving current auth status and continuing auto-reconnect evaluation"
                .to_string(),
        );
        drop(s);
        crate::service::request_ui_repaint();
    }
    // ── Layer 2+3: Auth Server + Auth Status ─────
    if !sync_online_state_from_interfaces(
        state,
        &interfaces,
        auth_generation,
        initial_query_generation,
        from_cache,
    )
    .await
    {
        return interval;
    }
    let completed_query_generation = initial_query_generation.wrapping_add(1);
    // A cached query may have detected trouble and refreshed its address/IP
    // before applying a result. Diagnose and reconnect using that fresh data.
    let (interfaces, users, statuses) = {
        let s = state.lock().unwrap();
        (
            s.network_interfaces.clone().unwrap_or(interfaces),
            s.config.users.clone(),
            s.user_statuses.clone(),
        )
    };
    let has_usable_ip = any_usable_user_ip(&users, &statuses, &interfaces);

    // ── Layer 4: IPv4 Internet (conditional) ─────
    let (
        probe_enabled,
        probe_auth_generation,
        probe_query_generation,
        probe_server,
        probe_campus_ip,
    ) = {
        let s = state.lock().unwrap();
        if s.authentication_busy()
            || s.online_query_busy
            || s.auth_generation != auth_generation
            || s.online_query_generation != completed_query_generation
        {
            return interval;
        }
        (
            s.config.enable_ipv4_internet_probe,
            s.auth_generation,
            s.online_query_generation,
            s.config.server.clone(),
            s.campus_ip.clone(),
        )
    };

    if probe_enabled {
        let probe_ip = {
            let s = state.lock().unwrap();
            ipv4_probe_ip(&s, &interfaces)
        };
        if let Some(bind_ip) = probe_ip.as_deref() {
            let ipv4_status = check_ipv4_reachability(&probe_server, Some(bind_ip)).await;
            {
                let mut s = state.lock().unwrap();
                if !s.config.enable_ipv4_internet_probe {
                    s.ipv4_internet = Ipv4InternetStatus::Disabled;
                    drop(s);
                    crate::service::request_ui_repaint();
                    return interval;
                }
                if !apply_ipv4_probe(
                    &mut s,
                    ipv4_status,
                    probe_auth_generation,
                    probe_query_generation,
                    &probe_campus_ip,
                ) {
                    return interval;
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
            drop(s);
            crate::service::request_ui_repaint();
        }
    } else {
        let mut s = state.lock().unwrap();
        s.ipv4_internet = Ipv4InternetStatus::Disabled;
        drop(s);
        crate::service::request_ui_repaint();
    }

    // ── Auto-reconnect ──────────────────────────
    let (decision, mut reconnect_generation) = {
        let s = state.lock().unwrap();
        if s.authentication_busy()
            || s.online_query_busy
            || s.auth_generation != auth_generation
            || s.online_query_generation != completed_query_generation
        {
            return interval;
        }
        (evaluate_reconnect(&s, has_usable_ip), s.auth_generation)
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
                drop(s);
                crate::service::request_ui_repaint();
            }
            interval
        }

        ReconnectDecision::Wait => interval,

        ReconnectDecision::Reconnect => {
            let (targets, created_targets) = {
                let mut s = state.lock().unwrap();
                if s.auth_generation != reconnect_generation
                    || !matches!(
                        evaluate_reconnect(&s, has_usable_ip),
                        ReconnectDecision::Reconnect
                    )
                {
                    return interval;
                }
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
                let targets: Vec<_> = s
                    .reconnect_targets
                    .iter()
                    .filter_map(|&idx| s.config.users.get(idx).cloned().map(|user| (idx, user)))
                    .collect();
                (targets, created_targets)
            };
            if created_targets {
                crate::service::request_ui_repaint();
            }

            if targets.is_empty() {
                return interval;
            }

            let mut any_portal_ok = false;
            for (idx, user) in &targets {
                if !do_auto_login(state.clone(), *idx, user, reconnect_generation).await {
                    return interval;
                }
                // Only our own claim/release may advance this batch. Never
                // adopt a newer generation produced by a manual operation.
                reconnect_generation = reconnect_generation.wrapping_add(2);
                let post_state = {
                    let s = state.lock().unwrap();
                    if s.auth_generation != reconnect_generation {
                        return interval;
                    }
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
                if s.auth_generation != reconnect_generation {
                    return interval;
                }
                s.reconnect_targets.clear();
                s.online_info_fail_count = 0;
                s.add_log(
                    "[OK] Auto-reconnect login request succeeded, waiting for server confirmation"
                        .to_string(),
                );
                drop(s);
                crate::service::request_ui_repaint();
                interval
            } else {
                let mut s = state.lock().unwrap();
                if s.auth_generation != reconnect_generation {
                    return interval;
                }
                let next = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                s.add_log(format!(
                    "[WARN] Auto-reconnect failed, will retry in {}s",
                    next
                ));
                drop(s);
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
    fn only_confirmed_online_sessions_reuse_a_nonempty_ipv4_snapshot() {
        let mut s = make_state();
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.online_info = Some(crate::service::OnlineUserInfo::default());
        assert!(cached_online_interfaces(&s).is_none());
        s.network_interfaces = Some(vec![("test-campus".into(), "10.0.0.2".parse().unwrap())]);
        assert!(cached_online_interfaces(&s).is_some());
        s.online_info_stale = true;
        assert!(cached_online_interfaces(&s).is_none());
        s.online_info_stale = false;
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        assert!(cached_online_interfaces(&s).is_none());
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.network_interfaces = Some(Vec::new());
        assert!(cached_online_interfaces(&s).is_none());
        s.network_interfaces = Some(vec![("test-ipv6".into(), "::1".parse().unwrap())]);
        assert!(cached_online_interfaces(&s).is_none());
    }

    #[test]
    fn tun_internet_success_does_not_erase_the_offline_accounts_reconnect_target() {
        let mut s = make_state();
        s.config.enable_ipv4_internet_probe = true;
        s.campus_ip = Some("10.0.0.2".into());
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        s.config.users = ["test-first", "test-previous-online"]
            .into_iter()
            .map(|name| StoredUser {
                username: name.into(),
                encrypted_password: String::new(),
                ip: None,
                if_name: None,
            })
            .collect();
        s.ensure_statuses();
        s.user_statuses[1].state = LoginState::Error;
        s.reconnect_targets = vec![1];
        let auth_generation = s.auth_generation;
        let query_generation = s.online_query_generation;
        let campus_ip = s.campus_ip.clone();
        assert!(apply_ipv4_probe(
            &mut s,
            Ipv4InternetStatus::Reachable,
            auth_generation,
            query_generation,
            &campus_ip,
        ));
        assert_eq!(s.campus_auth, CampusAuthStatus::NotLoggedIn);
        assert_eq!(s.reconnect_targets, vec![1]);
        assert!(reconnect_needed(&s, true));
        s.suppress_auto_reconnect = true;
        assert!(!reconnect_needed(&s, true));
    }

    #[test]
    fn optional_probe_follows_the_account_interface_instead_of_the_global_ip() {
        let mut s = make_state();
        s.campus_ip = Some("10.0.0.99".into());
        s.config.users.push(StoredUser {
            username: "test-bound-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: Some("test-campus".into()),
        });
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.2".into();
        let interfaces = vec![
            ("test-other".into(), "10.0.0.99".parse().unwrap()),
            ("test-campus".into(), "10.0.0.2".parse().unwrap()),
        ];
        assert_eq!(ipv4_probe_ip(&s, &interfaces).as_deref(), Some("10.0.0.2"));
        s.user_statuses[0].state = LoginState::Error;
        s.reconnect_targets = vec![0];
        assert_eq!(ipv4_probe_ip(&s, &interfaces).as_deref(), Some("10.0.0.2"));
        s.campus_ip = None;
        assert!(ipv4_probe_ip(&s, &interfaces).is_none());
    }

    #[test]
    fn uncertain_or_tun_affected_diagnostics_do_not_override_authoritative_state() {
        for (auth, failures, enabled, internet) in [
            (
                CampusAuthStatus::LoggedIn,
                0,
                true,
                Ipv4InternetStatus::Unreachable,
            ),
            (
                CampusAuthStatus::LoggedIn,
                0,
                true,
                Ipv4InternetStatus::CaptivePortal,
            ),
            (
                CampusAuthStatus::Unknown,
                2,
                true,
                Ipv4InternetStatus::CaptivePortal,
            ),
            (
                CampusAuthStatus::Unknown,
                3,
                false,
                Ipv4InternetStatus::CaptivePortal,
            ),
            (
                CampusAuthStatus::Unknown,
                3,
                true,
                Ipv4InternetStatus::ProbeFailed,
            ),
        ] {
            let mut s = make_state();
            s.campus_ip = Some("10.0.0.2".into());
            s.campus_auth = auth;
            s.online_info_fail_count = failures;
            s.config.enable_ipv4_internet_probe = enabled;
            s.ipv4_internet = internet;
            assert!(!reconnect_needed(&s, true));
        }
    }

    #[test]
    fn turning_off_probes_rejects_cached_fallback_authentication_state() {
        let mut s = make_state();
        s.campus_ip = Some("10.0.0.2".into());
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        s.online_info_fail_count = 3;
        s.config.enable_ipv4_internet_probe = true;
        s.ipv4_internet = Ipv4InternetStatus::CaptivePortal;
        assert!(reconnect_needed(&s, true));
        s.config.enable_ipv4_internet_probe = false;
        assert!(!s.definitely_offline());
        assert!(!reconnect_needed(&s, true));
        for failures in [1, 2] {
            s.online_info_fail_count = failures;
            assert!(!s.definitely_offline());
            assert!(!reconnect_needed(&s, true));
        }
        // A fresh server offline response remains authoritative with probes off.
        s.online_info_fail_count = 0;
        assert!(s.definitely_offline());
        assert!(reconnect_needed(&s, true));
        s.suppress_auto_reconnect = true;
        assert!(!reconnect_needed(&s, true));
    }

    #[test]
    fn delayed_ipv4_probe_does_not_overwrite_a_new_context() {
        for change in 0..4 {
            let mut s = make_state();
            s.config.enable_ipv4_internet_probe = true;
            s.campus_ip = Some("10.0.0.1".into());
            s.internet_fail_count = 1;
            s.ipv4_internet = Ipv4InternetStatus::Checking;
            let ip = s.campus_ip.clone();
            let auth_generation = s.auth_generation;
            let query_generation = s.online_query_generation;
            match change {
                0 => s.invalidate_auth_context(),
                1 => s.online_query_generation += 1,
                2 => s.campus_ip = Some("10.0.0.2".into()),
                _ => s.config.enable_ipv4_internet_probe = false,
            }
            assert!(!apply_ipv4_probe(
                &mut s,
                Ipv4InternetStatus::CaptivePortal,
                auth_generation,
                query_generation,
                &ip
            ));
            assert_eq!(s.internet_fail_count, 1);
            assert_eq!(s.ipv4_internet, Ipv4InternetStatus::Checking);
        }
    }

    #[test]
    fn reconnect_waits_during_authentication() {
        for login_state in [LoginState::LoggingIn, LoginState::LoggingOut] {
            let mut s = make_state();
            s.campus_ip = Some("10.0.0.1".to_string());
            s.campus_auth = CampusAuthStatus::NotLoggedIn;
            s.config.users.push(StoredUser {
                username: "test-user".to_string(),
                encrypted_password: String::new(),
                ip: None,
                if_name: None,
            });
            s.ensure_statuses();
            s.user_statuses[0].state = login_state;
            assert!(matches!(
                evaluate_reconnect(&s, any_usable_ip(&s)),
                ReconnectDecision::Wait
            ));
        }
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
        let interfaces = vec![("test-campus".into(), "10.0.0.2".parse().unwrap())];

        let mut s = make_state();
        s.config.users.push(StoredUser {
            username: "test".to_string(),
            encrypted_password: String::new(),
            ip: None,
            if_name: Some("test-campus".into()),
        });
        s.ensure_statuses();
        assert!(any_usable_user_ip(
            &s.config.users,
            &s.user_statuses,
            &interfaces
        ));
        assert!(!any_usable_user_ip(&s.config.users, &s.user_statuses, &[]));
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
            evaluate_reconnect(&s, any_usable_ip(&s)),
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
            evaluate_reconnect(&s, any_usable_ip(&s)),
            ReconnectDecision::Reconnect
        ));
    }

    #[test]
    fn no_reconnect_without_any_ip() {
        let mut s = make_state();
        s.config.auto_reconnect = true;
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        assert!(matches!(
            evaluate_reconnect(&s, any_usable_ip(&s)),
            ReconnectDecision::Wait
        ));
    }
}
