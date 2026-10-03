use std::time::Duration;

use serde::Deserialize;

use crate::service::detection::{check_auth_server, check_auth_status, detect_campus_ip};
use crate::service::user_ip;
use crate::service::{AuthServerStatus, CampusAuthStatus, LoginState, SharedState};

/// Parsed from /cgi-bin/rad_user_info?callback=sdu JSONP response.
/// All fields have defaults — the API may change over srun versions.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OnlineUserInfo {
    /// "ok" means logged in; explicit not_online codes mean offline.
    pub error: String,
    pub user_name: String,
    pub online_ip: String,
    pub add_time: u64,
    pub keepalive_time: u64,
    pub sum_bytes: u64,
    pub sum_seconds: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub remain_bytes: u64,
    pub remain_seconds: u64,
    pub products_name: String,
    pub user_balance: u32,
    pub wallet_balance: u32,
    pub user_mac: String,
    pub real_name: String,
    pub sysver: String,
}

/// Result of matching a server-reported user_name against locally configured
/// accounts. Callers must handle each variant explicitly — there is no
/// implicit "first match" fallback.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchResult {
    /// Exact string match: local `username` == server `user_name`.
    Exact(usize),
    /// Local user has suffix (e.g. `abc@cmcc`), server returned base (`abc`),
    /// and exactly one local candidate shares the base. Safe to confirm.
    UniqueBase(usize),
    /// Multiple local users share the same base username — cannot safely
    /// determine which one the server refers to.
    Ambiguous(Vec<usize>),
    /// No local user matches the server-reported user_name.
    NoMatch,
}

/// Match a server-reported `user_name` against locally configured users.
///
/// Rules (in priority order):
/// 1. Exact string match → `Exact(idx)`.
/// 2. Server name is a base (no `@`), and exactly one local user has
///    `base@something` → `UniqueBase(idx)`.
/// 3. Server name is a base, multiple locals share it → `Ambiguous(indices)`.
/// 4. No match → `NoMatch`.
pub fn match_account(
    server_user: &str,
    local_users: &[crate::service::config::StoredUser],
) -> MatchResult {
    let server = server_user.trim();

    // ── Rule 1: exact match ────────────────────────────
    for (idx, u) in local_users.iter().enumerate() {
        if u.username.trim() == server {
            return MatchResult::Exact(idx);
        }
    }

    // ── Rule 2+3: base-name matching ──────────────────
    // Only applicable when server returns a bare username (no '@')
    if server.contains('@') {
        return MatchResult::NoMatch;
    }

    let candidates: Vec<usize> = local_users
        .iter()
        .enumerate()
        .filter(|(_, u)| {
            let local = u.username.trim();
            local
                .strip_prefix(server)
                .is_some_and(|suffix| suffix.starts_with('@') && suffix.len() > 1)
        })
        .map(|(i, _)| i)
        .collect();

    match candidates.len() {
        0 => MatchResult::NoMatch,
        1 => MatchResult::UniqueBase(candidates[0]),
        _ => MatchResult::Ambiguous(candidates),
    }
}

/// If `online_info` matches a single local account, return its index.
/// Returns `None` when online_info is None, the match is ambiguous,
/// or no local user matches.
pub fn confirmed_online_user_idx(
    online_info: Option<&OnlineUserInfo>,
    users: &[crate::service::config::StoredUser],
) -> Option<usize> {
    let info = online_info?;
    match match_account(&info.user_name, users) {
        MatchResult::Exact(idx) | MatchResult::UniqueBase(idx) => Some(idx),
        MatchResult::Ambiguous(_) | MatchResult::NoMatch => None,
    }
}

/// Fetch online user info from the auth server's rad_user_info endpoint.
///
/// Returns:
/// - `Ok(Some(info))` — successfully fetched and `error == "ok"` (logged in)
/// - `Ok(None)` — server explicitly reports `not_online` / `not_online_error`
/// - `Err(msg)` — request or parse failed entirely (server unreachable etc.)
pub async fn fetch_online_user_info(
    server: &str,
    campus_ipv4: Option<&str>,
) -> Result<Option<OnlineUserInfo>, String> {
    let server = crate::core::srun::SrunClient::normalize_server_url(server);
    if server.is_empty() {
        return Err("No server URL configured".to_string());
    }

    let (client, _bound) = crate::service::http_client::build_probe_client(
        Duration::from_secs(2),
        Duration::from_secs(5),
        campus_ipv4,
    )
    .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let url = format!("{}/cgi-bin/rad_user_info", server);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    tracing::debug!(
        "[OnlineInfo] Querying: url={} campus_ipv4={:?}",
        url,
        campus_ipv4
    );

    let resp = client
        .get(&url)
        .query(&[("callback", "sdu"), ("_", &ts)])
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e.without_url()))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e.without_url()))?;

    parse_online_user_info(&body)
}

fn parse_online_user_info(bytes: &[u8]) -> Result<Option<OnlineUserInfo>, String> {
    let body = crate::core::srun::decode_body(bytes);
    let json_str = crate::core::jsonp::strip_jsonp(&body)?;

    let info: OnlineUserInfo =
        serde_json::from_str(json_str).map_err(|_| "Invalid rad_user_info JSON".to_string())?;

    if info.error == "ok" {
        if info.user_name.trim().is_empty() {
            return Err("Online status is missing the account name".to_string());
        }
        tracing::debug!(
            "[OnlineInfo] User online: user_name={} ip={} sum_seconds={}",
            info.user_name,
            info.online_ip,
            info.sum_seconds
        );
        Ok(Some(info))
    } else if matches!(info.error.as_str(), "not_online" | "not_online_error") {
        tracing::debug!("[OnlineInfo] Not logged in: error={}", info.error);
        Ok(None)
    } else {
        Err("Unrecognized rad_user_info status; login state is unknown".to_string())
    }
}

/// Apply a match result to user statuses — pure function, testable.
///
/// - `Exact` / `UniqueBase`: the matching user → `Online`, others with
///   `Online` or `PendingConfirm` → `Error` (another account is online).
/// - `Ambiguous`: matching candidates that were `PendingConfirm` stay
///   `PendingConfirm`; `Online` users among candidates are demoted to `Error`.
///   No user is promoted to `Online`.
/// - `NoMatch`: any `Online` or `PendingConfirm` user → `Error`.
pub fn apply_match_result(
    match_result: &MatchResult,
    user_statuses: &mut [crate::service::UserStatus],
    server_user: &str,
    server_ip: &str,
) {
    match match_result {
        MatchResult::Exact(idx) | MatchResult::UniqueBase(idx) => {
            for (i, us) in user_statuses.iter_mut().enumerate() {
                if matches!(us.state, LoginState::LoggingIn | LoginState::LoggingOut) {
                    continue;
                }
                if i == *idx {
                    us.state = LoginState::Online;
                    us.current_ip = server_ip.to_string();
                    us.last_error.clear();
                } else if us.state == LoginState::Online || us.state == LoginState::PendingConfirm {
                    us.state = LoginState::Error;
                    us.last_error = format!("Another account is online: {}", server_user);
                }
            }
        }
        MatchResult::Ambiguous(indices) => {
            for (i, us) in user_statuses.iter_mut().enumerate() {
                if indices.contains(&i) {
                    if us.state == LoginState::Online {
                        us.state = LoginState::Error;
                        us.last_error =
                            format!("Ambiguous server match — cannot confirm: {}", server_user);
                    }
                    // PendingConfirm stays PendingConfirm — not promoted to Online
                } else if us.state == LoginState::Online || us.state == LoginState::PendingConfirm {
                    us.state = LoginState::Error;
                    us.last_error = format!("Another account is online: {}", server_user);
                }
            }
        }
        MatchResult::NoMatch => {
            for us in user_statuses.iter_mut() {
                if us.state == LoginState::Online || us.state == LoginState::PendingConfirm {
                    us.state = LoginState::Error;
                    us.last_error = format!("Another account is online: {}", server_user);
                }
            }
        }
    }
}

/// Pick the best IP to bind rad_user_info queries to.
///
/// Priority:
/// 1. `Online` user's `current_ip`
/// 2. `PendingConfirm` user's `current_ip`
/// 3. `reconnect_targets`中第一个有 `user.ip` 的用户 IP
/// 4. 全局 `campus_ip`（real-time detected, more reliable than stored IP）
/// 5. 任一配置用户的 `user.ip`（last resort when auto-detection fails）
pub fn best_status_query_ip(s: &crate::service::AppState) -> Option<String> {
    // 1. Online.current_ip
    if let Some(us) = s
        .user_statuses
        .iter()
        .find(|us| us.state == LoginState::Online)
    {
        if !us.current_ip.is_empty() {
            return Some(us.current_ip.clone());
        }
    }
    // 2. PendingConfirm.current_ip
    if let Some(us) = s
        .user_statuses
        .iter()
        .find(|us| us.state == LoginState::PendingConfirm)
    {
        if !us.current_ip.is_empty() {
            return Some(us.current_ip.clone());
        }
    }
    // 3. reconnect_targets 中第一个有 user.ip 的用户
    for &idx in &s.reconnect_targets {
        if let Some(user) = s.config.users.get(idx) {
            if let Some(ip) = user_ip::configured_static_ip(user) {
                return Some(ip);
            }
        }
    }
    // 4. 全局 campus_ip
    if let Some(ref ip) = s.campus_ip {
        if !ip.is_empty() {
            return Some(ip.clone());
        }
    }
    // 5. 任一配置用户的 user.ip（last resort）
    for user in &s.config.users {
        if let Some(ip) = user_ip::configured_static_ip(user) {
            return Some(ip);
        }
    }
    None
}

/// Called at startup and periodically by the monitor.
struct StatusQuery {
    server: String,
    ip: Option<String>,
    auth_generation: u64,
    query_generation: u64,
}

impl StatusQuery {
    fn begin(s: &mut crate::service::AppState) -> Option<Self> {
        if s.authentication_busy() || s.online_query_busy {
            return None;
        }
        s.online_query_busy = true;
        s.online_query_generation = s.online_query_generation.wrapping_add(1);
        Some(Self {
            server: s.config.server.clone(),
            ip: best_status_query_ip(s),
            auth_generation: s.auth_generation,
            query_generation: s.online_query_generation,
        })
    }

    fn is_current(&self, s: &crate::service::AppState) -> bool {
        !s.authentication_busy()
            && self.auth_generation == s.auth_generation
            && self.query_generation == s.online_query_generation
            && self.server == s.config.server
            && self.ip == best_status_query_ip(s)
    }

    fn finish(&self, s: &mut crate::service::AppState) {
        if self.query_generation == s.online_query_generation {
            s.online_query_busy = false;
        }
    }
}

struct StatusQueryGuard {
    state: SharedState,
    query: StatusQuery,
}

impl Drop for StatusQueryGuard {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.query.finish(&mut s);
        drop(s);
        crate::service::request_ui_repaint();
    }
}

pub async fn sync_online_state(state: &SharedState) {
    let query = {
        let mut s = state.lock().unwrap();
        let Some(query) = StatusQuery::begin(&mut s) else {
            return;
        };
        query
    };
    let guard = StatusQueryGuard {
        state: state.clone(),
        query,
    };
    let query = &guard.query;
    crate::service::request_ui_repaint();
    let (server, query_ip) = (&query.server, &query.ip);

    match fetch_online_user_info(server, query_ip.as_deref()).await {
        Ok(Some(info)) => {
            let mut s = state.lock().unwrap();
            if !query.is_current(&s) {
                return;
            }
            s.auth_server = AuthServerStatus::Reachable;
            s.campus_auth = CampusAuthStatus::LoggedIn;
            s.online_info = Some(info.clone());
            s.online_info_fail_count = 0;
            s.online_info_stale = false;

            let match_result = match_account(&info.user_name, &s.config.users);
            apply_match_result(
                &match_result,
                &mut s.user_statuses,
                &info.user_name,
                &info.online_ip,
            );
            match &match_result {
                MatchResult::Exact(idx) => {
                    let uname = s.config.users[*idx].username.clone();
                    let ip = info.online_ip.clone();
                    s.add_log(format!(
                        "[OK] {} confirmed online by server, IP={}",
                        uname, ip
                    ));
                }
                MatchResult::UniqueBase(idx) => {
                    let uname = s.config.users[*idx].username.clone();
                    let ip = info.online_ip.clone();
                    s.add_log(format!(
                        "[OK] {} (base match) confirmed online by server, IP={}",
                        uname, ip
                    ));
                }
                MatchResult::Ambiguous(indices) => {
                    let names: Vec<String> = indices
                        .iter()
                        .map(|&i| s.config.users[i].username.clone())
                        .collect();
                    let ip = info.online_ip.clone();
                    let uname = info.user_name.clone();
                    s.add_log(format!(
                        "[WARN] Server reports online user {} (IP={}), matches multiple local accounts: {:?} — cannot confirm which one",
                        uname, ip, names
                    ));
                }
                MatchResult::NoMatch => {
                    s.add_log(format!(
                        "[WARN] Server reports online user {} (IP={}), not in local config",
                        info.user_name, info.online_ip
                    ));
                }
            }
            drop(s);
            crate::service::request_ui_repaint();
        }

        Ok(None) => {
            let mut s = state.lock().unwrap();
            if !query.is_current(&s) {
                return;
            }
            s.auth_server = AuthServerStatus::Reachable;
            s.campus_auth = CampusAuthStatus::NotLoggedIn;
            s.online_info = None;
            s.online_info_fail_count = 0;
            s.online_info_stale = false;

            // Invalidate users that were marked Online or PendingConfirm
            for us in &mut s.user_statuses {
                if us.state == LoginState::Online || us.state == LoginState::PendingConfirm {
                    us.state = LoginState::Error;
                    us.last_error = "Server reports no user logged in".to_string();
                }
            }
            s.add_log("[INFO] Auth server reachable, no user logged in".to_string());
            drop(s);
            crate::service::request_ui_repaint();
        }

        Err(msg) => {
            let (_fail_count, degraded) = {
                let mut s = state.lock().unwrap();
                if !query.is_current(&s) {
                    return;
                }
                s.online_info_fail_count = s.online_info_fail_count.saturating_add(1);
                s.online_info_stale = true;
                let fc = s.online_info_fail_count;
                if fc <= 2 {
                    s.add_log(format!(
                        "[WARN] rad_user_info query failed ({}/3): {}",
                        fc, msg
                    ));
                    (fc, false)
                } else {
                    s.add_log(format!(
                        "[WARN] rad_user_info degraded to fallback after {} failures",
                        fc
                    ));
                    (fc, true)
                }
            }; // MutexGuard dropped here before any await

            if degraded {
                let auth_server = check_auth_server(server, query_ip.as_deref()).await;
                let reachable = auth_server == AuthServerStatus::Reachable;
                let probe_enabled = {
                    let s = state.lock().unwrap();
                    s.config.enable_ipv4_internet_probe
                };
                {
                    let mut s = state.lock().unwrap();
                    if !query.is_current(&s) {
                        return;
                    }
                    s.auth_server = auth_server;
                    if !reachable {
                        s.campus_auth = CampusAuthStatus::Unknown;
                    }
                }
                if reachable {
                    if probe_enabled {
                        let auth_status = check_auth_status(query_ip.as_deref()).await;
                        let mut s = state.lock().unwrap();
                        if !query.is_current(&s) || !s.config.enable_ipv4_internet_probe {
                            return;
                        }
                        s.campus_auth = auth_status;
                    } else {
                        // IPv4 internet probe disabled — do NOT call check_auth_status()
                        // which would access http://www.baidu.com
                        let mut s = state.lock().unwrap();
                        if !query.is_current(&s) {
                            return;
                        }
                        s.campus_auth = CampusAuthStatus::Unknown;
                        s.add_log(
                            "[WARN] rad_user_info failed, IPv4 internet probe disabled; skipping captive portal probe, auth state remains Unknown".to_string(),
                        );
                    }
                }
            }
            crate::service::request_ui_repaint();
        }
    }
}

/// Startup orchestration: version check → online state sync → conditional auto-login → monitor.
/// Called once from main.rs, replaces direct spawn_monitor().
/// Pure predicate: should the startup auto-login fire?
pub fn should_auto_login(
    auto_reconnect: bool,
    has_online: bool,
    user_count: usize,
    campus_auth: &CampusAuthStatus,
) -> bool {
    if !auto_reconnect || has_online || user_count == 0 {
        return false;
    }
    matches!(campus_auth, CampusAuthStatus::NotLoggedIn)
}

pub fn spawn_startup_tasks(state: SharedState) {
    tokio::spawn(async move {
        // Phase 1 (version check) is now handled by update_scheduler.
        // ── Phase 2: Detect campus IP ──────────────────
        {
            let ip = detect_campus_ip();
            let mut s = state.lock().unwrap();
            s.campus_ip = ip;
        }
        crate::service::request_ui_repaint();

        // ── Phase 3: Sync online state from server ─────
        sync_online_state(&state).await;

        // ── Phase 4: Conditional auto-login ────────────
        let (auto_reconnect, should_login, has_online, campus_auth, generation, first_user) = {
            let s = state.lock().unwrap();
            let has_online = s
                .user_statuses
                .iter()
                .any(|us| us.state == LoginState::Online || us.state == LoginState::PendingConfirm);
            (
                s.config.auto_reconnect,
                s.config.users.len(),
                has_online,
                s.campus_auth.clone(),
                s.auth_generation,
                s.config.users.first().cloned(),
            )
        };
        if should_auto_login(auto_reconnect, has_online, should_login, &campus_auth) {
            tracing::info!(
                "[Startup] Auto-reconnect enabled, not logged in — starting one-click login"
            );
            {
                let mut s = state.lock().unwrap();
                s.add_log("[INFO] Auto-login on startup...".to_string());
            }
            crate::service::request_ui_repaint();
            if let Some(user) = first_user {
                crate::service::auth::do_startup_login(state.clone(), user, generation).await;
            }
            // Re-sync after login attempt
            sync_online_state(&state).await;
        } else if auto_reconnect
            && !has_online
            && should_login > 0
            && campus_auth == CampusAuthStatus::Unknown
        {
            tracing::info!(
                "[Startup] Auth state unknown; skip startup auto-login and wait for monitor/manual refresh"
            );
            let mut s = state.lock().unwrap();
            s.add_log(
                "[INFO] Auth state unknown; skipping auto-login, waiting for monitor".to_string(),
            );
        }

        // ──

        // ── Phase 5: Start periodic monitor ────────────
        crate::service::monitor::spawn_monitor(state);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::config::StoredUser;

    fn make_user(name: &str) -> StoredUser {
        StoredUser {
            username: name.to_string(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        }
    }

    #[test]
    fn malformed_status_is_unknown_instead_of_offline() {
        for body in [r#"{}"#, r#"{"error":"ip_error"}"#, r#"{"error":"ok"}"#] {
            let response = format!("sdu({body})");
            assert!(
                parse_online_user_info(response.as_bytes()).is_err(),
                "misclassified response: {body}"
            );
        }
    }

    #[test]
    fn explicit_offline_status_and_online_gbk_are_supported() {
        for error in ["not_online", "not_online_error"] {
            let body = format!(r#"sdu({{"error":"{error}"}})"#);
            assert!(parse_online_user_info(body.as_bytes()).unwrap().is_none());
        }
        let body = r#"sdu({"error":"ok","user_name":"测试账号","online_ip":"10.0.0.1"})"#;
        let (bytes, _, had_errors) = encoding_rs::GBK.encode(body);
        assert!(!had_errors);
        let info = parse_online_user_info(&bytes).unwrap().unwrap();
        assert_eq!(info.user_name, "测试账号");
    }

    // ── match_account tests ───────────────────────────────

    #[test]
    fn outdated_status_queries_are_discarded() {
        let mut s = make_app_state();
        let first = StatusQuery::begin(&mut s).unwrap();
        s.invalidate_auth_context();
        let second = StatusQuery::begin(&mut s).unwrap();
        assert!(!first.is_current(&s));
        assert!(second.is_current(&s));
        s.invalidate_auth_context();
        assert!(!second.is_current(&s));
    }

    #[test]
    fn repeated_refresh_does_not_discard_a_running_status_query() {
        let mut s = make_app_state();
        let first = StatusQuery::begin(&mut s).unwrap();
        assert!(StatusQuery::begin(&mut s).is_none());
        assert!(first.is_current(&s));
    }

    #[test]
    fn status_queries_cannot_overwrite_auth_or_changed_server_ip() {
        let mut s = make_app_state();
        let query = StatusQuery::begin(&mut s).unwrap();
        s.auth_busy = true;
        assert!(!query.is_current(&s));
        assert!(StatusQuery::begin(&mut s).is_none());
        s.auth_busy = false;
        s.config.server = "http://other.invalid".into();
        assert!(!query.is_current(&s));
        query.finish(&mut s);
        let query = StatusQuery::begin(&mut s).unwrap();
        s.campus_ip = Some("10.0.0.2".into());
        assert!(!query.is_current(&s));
    }

    #[test]
    fn old_status_completion_cannot_release_a_new_query() {
        let mut s = make_app_state();
        let old = StatusQuery::begin(&mut s).unwrap();
        s.invalidate_auth_context();
        let new = StatusQuery::begin(&mut s).unwrap();
        old.finish(&mut s);
        assert!(s.online_query_busy);
        assert!(new.is_current(&s));
        new.finish(&mut s);
        assert!(!s.online_query_busy);
    }

    #[test]
    fn dropped_status_task_releases_refresh_controls() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(make_app_state()));
        let query = StatusQuery::begin(&mut state.lock().unwrap()).unwrap();
        let guard = StatusQueryGuard {
            state: state.clone(),
            query,
        };
        assert!(state.lock().unwrap().online_query_busy);
        drop(guard);
        assert!(!state.lock().unwrap().online_query_busy);
    }

    #[test]
    fn match_exact() {
        let users = vec![make_user("abc"), make_user("def@cmcc")];
        assert_eq!(match_account("abc", &users), MatchResult::Exact(0));
        assert_eq!(match_account("def@cmcc", &users), MatchResult::Exact(1));
    }

    #[test]
    fn match_exact_trimmed() {
        let users = vec![make_user(" abc "), make_user("def@cmcc")];
        assert_eq!(match_account("abc", &users), MatchResult::Exact(0));
    }

    #[test]
    fn match_unique_base_single_candidate() {
        let users = vec![make_user("abc@cmcc")];
        assert_eq!(match_account("abc", &users), MatchResult::UniqueBase(0));
    }

    #[test]
    fn match_unique_base_multiple_users_one_match() {
        let users = vec![make_user("xyz"), make_user("abc@cmcc")];
        assert_eq!(match_account("abc", &users), MatchResult::UniqueBase(1));
    }

    #[test]
    fn match_ambiguous() {
        let users = vec![make_user("abc@cmcc"), make_user("abc@unicom")];
        let result = match_account("abc", &users);
        assert!(matches!(result, MatchResult::Ambiguous(ref v) if v.len() == 2));
    }

    #[test]
    fn match_no_match() {
        let users = vec![make_user("abc@cmcc")];
        assert_eq!(match_account("def", &users), MatchResult::NoMatch);
    }

    #[test]
    fn match_server_has_at_no_base_match() {
        let users = vec![make_user("abc")];
        // Server returns "abc@cmcc" — has '@', so NoMatch even though base matches
        assert_eq!(match_account("abc@cmcc", &users), MatchResult::NoMatch);
    }

    #[test]
    fn match_no_users() {
        let users: Vec<StoredUser> = vec![];
        assert_eq!(match_account("abc", &users), MatchResult::NoMatch);
    }

    // ── should_auto_login tests ───────────────────────────

    #[test]
    fn auto_login_off() {
        assert!(!should_auto_login(
            false,
            false,
            1,
            &CampusAuthStatus::NotLoggedIn
        ));
    }

    #[test]
    fn auto_login_has_online() {
        assert!(!should_auto_login(
            true,
            true,
            1,
            &CampusAuthStatus::NotLoggedIn
        ));
    }

    #[test]
    fn auto_login_no_users() {
        assert!(!should_auto_login(
            true,
            false,
            0,
            &CampusAuthStatus::NotLoggedIn
        ));
    }

    #[test]
    fn auto_login_not_logged_in() {
        assert!(should_auto_login(
            true,
            false,
            1,
            &CampusAuthStatus::NotLoggedIn
        ));
    }

    #[test]
    fn auto_login_unknown_skipped() {
        assert!(!should_auto_login(
            true,
            false,
            1,
            &CampusAuthStatus::Unknown
        ));
    }

    #[test]
    fn auto_login_logged_in_skipped() {
        assert!(!should_auto_login(
            true,
            false,
            1,
            &CampusAuthStatus::LoggedIn
        ));
    }

    // ── best_status_query_ip tests ────────────────────────

    use crate::service::config::AppConfig;
    use crate::service::AppState;

    fn make_app_state() -> AppState {
        AppState::new(AppConfig::default())
    }

    #[test]
    fn query_ip_online_current_ip() {
        let mut s = make_app_state();
        s.config.users.push(make_user("u1"));
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.1".to_string();
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.1".to_string()));
    }

    #[test]
    fn query_ip_pending_current_ip() {
        let mut s = make_app_state();
        s.config.users.push(make_user("u1"));
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::PendingConfirm;
        s.user_statuses[0].current_ip = "10.0.0.2".to_string();
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.2".to_string()));
    }

    #[test]
    fn query_ip_reconnect_target_user_ip() {
        let mut s = make_app_state();
        s.config.users.push(StoredUser {
            username: "u1".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.3".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        s.reconnect_targets = vec![0];
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.3".to_string()));
    }

    #[test]
    fn query_ip_first_configured_user_ip() {
        let mut s = make_app_state();
        s.config.users.push(StoredUser {
            username: "u1".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.4".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.4".to_string()));
    }

    #[test]
    fn query_ip_fallback_campus_ip() {
        let mut s = make_app_state();
        s.campus_ip = Some("10.0.0.5".to_string());
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.5".to_string()));
    }

    #[test]
    fn query_ip_none() {
        let s = make_app_state();
        assert_eq!(best_status_query_ip(&s), None);
    }

    #[test]
    fn query_ip_reconnect_target_over_campus_ip() {
        let mut s = make_app_state();
        s.campus_ip = Some("10.0.0.10".to_string());
        s.config.users.push(StoredUser {
            username: "u1".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.3".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        s.reconnect_targets = vec![0];
        // reconnect_target user.ip should beat campus_ip
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.3".to_string()));
    }

    #[test]
    fn query_ip_campus_over_arbitrary_user_ip() {
        let mut s = make_app_state();
        s.campus_ip = Some("10.0.0.5".to_string());
        s.config.users.push(StoredUser {
            username: "u1".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.4".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        // campus_ip (real-time) beats arbitrary saved user.ip
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.5".to_string()));
    }

    #[test]
    fn query_ip_user_ip_fallback_when_no_campus() {
        let mut s = make_app_state();
        s.config.users.push(StoredUser {
            username: "u1".to_string(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.4".to_string()),
            if_name: None,
        });
        s.ensure_statuses();
        // No campus_ip — fallback to configured user.ip
        assert_eq!(best_status_query_ip(&s), Some("10.0.0.4".to_string()));
    }

    // ── apply_match_result tests ──────────────────────────

    fn make_status(state: LoginState) -> crate::service::UserStatus {
        crate::service::UserStatus {
            state,
            current_ip: String::new(),
            last_error: String::new(),
        }
    }

    #[test]
    fn status_sync_preserves_active_authentication() {
        for login_state in [LoginState::LoggingIn, LoginState::LoggingOut] {
            let mut statuses = vec![make_status(login_state.clone())];
            apply_match_result(
                &MatchResult::Exact(0),
                &mut statuses,
                "test-user",
                "10.0.0.1",
            );
            assert_eq!(statuses[0].state, login_state);
        }
    }

    #[test]
    fn apply_exact_sets_online_and_invalidates_others() {
        let mut statuses = vec![
            make_status(LoginState::LoggedOut),
            make_status(LoginState::PendingConfirm),
        ];
        apply_match_result(&MatchResult::Exact(0), &mut statuses, "alice", "10.0.0.1");
        assert_eq!(statuses[0].state, LoginState::Online);
        assert_eq!(statuses[0].current_ip, "10.0.0.1");
        assert_eq!(statuses[1].state, LoginState::Error);
    }

    #[test]
    fn apply_unique_base_confirms_single_candidate() {
        let mut statuses = vec![make_status(LoginState::PendingConfirm)];
        apply_match_result(
            &MatchResult::UniqueBase(0),
            &mut statuses,
            "alice",
            "10.0.0.2",
        );
        assert_eq!(statuses[0].state, LoginState::Online);
    }

    #[test]
    fn apply_ambiguous_does_not_set_online() {
        // Local: abc@cmcc (PendingConfirm), abc@unicom (LoggedOut)
        let mut statuses = vec![
            make_status(LoginState::PendingConfirm),
            make_status(LoginState::LoggedOut),
        ];
        apply_match_result(
            &MatchResult::Ambiguous(vec![0, 1]),
            &mut statuses,
            "abc",
            "10.0.0.3",
        );
        // Neither should be Online
        assert_ne!(statuses[0].state, LoginState::Online);
        assert_ne!(statuses[1].state, LoginState::Online);
        // PendingConfirm should stay PendingConfirm
        assert_eq!(statuses[0].state, LoginState::PendingConfirm);
    }

    #[test]
    fn apply_ambiguous_demotes_false_online() {
        // User 0 was Online but server says ambiguous
        let mut statuses = vec![make_status(LoginState::Online)];
        apply_match_result(
            &MatchResult::Ambiguous(vec![0]),
            &mut statuses,
            "abc",
            "10.0.0.4",
        );
        assert_eq!(statuses[0].state, LoginState::Error);
    }

    #[test]
    fn apply_no_match_does_not_set_online() {
        let mut statuses = vec![
            make_status(LoginState::PendingConfirm),
            make_status(LoginState::LoggedOut),
        ];
        apply_match_result(&MatchResult::NoMatch, &mut statuses, "xyz", "10.0.0.5");
        assert_ne!(statuses[0].state, LoginState::Online);
        assert_ne!(statuses[1].state, LoginState::Online);
        // PendingConfirm should be invalidated
        assert_eq!(statuses[0].state, LoginState::Error);
        assert_eq!(statuses[1].state, LoginState::LoggedOut);
    }

    // ── confirmed_online_user_idx tests ────────────────────

    fn make_online_info(user_name: &str) -> OnlineUserInfo {
        OnlineUserInfo {
            user_name: user_name.to_string(),
            error: "ok".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn confirmed_none_when_online_info_is_none() {
        let users = vec![make_user("abc@cmcc")];
        assert_eq!(confirmed_online_user_idx(None, &users), None);
    }

    #[test]
    fn confirmed_block_other_account() {
        // Server confirms account A (idx 0), target is B (idx 1) → block
        let info = make_online_info("alice@cmcc");
        let users = vec![make_user("alice@cmcc"), make_user("bob@cmcc")];
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), Some(0));
    }

    #[test]
    fn confirmed_same_account_not_blocked() {
        // Server confirms account A (idx 0), target is also A → no block
        let info = make_online_info("alice@cmcc");
        let users = vec![make_user("alice@cmcc"), make_user("bob@cmcc")];
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), Some(0));
    }

    #[test]
    fn confirmed_unique_base_block_other() {
        // Server returns "abc" (base), local has abc@cmcc (idx 0)
        // Target is another user (idx 1) → block (returns 0)
        let info = make_online_info("abc");
        let users = vec![make_user("abc@cmcc"), make_user("xyz@cmcc")];
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), Some(0));
    }

    #[test]
    fn confirmed_ambiguous_not_blocked() {
        // Server returns "abc" (base), local has abc@cmcc AND abc@unicom
        // Ambiguous → None (don't block)
        let info = make_online_info("abc");
        let users = vec![make_user("abc@cmcc"), make_user("abc@unicom")];
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), None);
    }

    #[test]
    fn confirmed_no_match_not_blocked() {
        // Server returns user not in local config → None (don't block)
        let info = make_online_info("stranger");
        let users = vec![make_user("alice@cmcc")];
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), None);
    }
}
