use std::time::Duration;

use serde::Deserialize;

use crate::service::detection::{
    check_auth_server, check_auth_status, detect_campus_ip_from_interfaces,
};
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
/// 1. A unique exact string match → `Exact(idx)`; duplicates → `Ambiguous`.
/// 2. Server name is a base (no `@`), and exactly one local user has
///    `base@something` → `UniqueBase(idx)`.
/// 3. Server name is a base, multiple locals share it → `Ambiguous(indices)`.
/// 4. No match → `NoMatch`.
pub fn match_account(
    server_user: &str,
    local_users: &[crate::service::config::StoredUser],
) -> MatchResult {
    let server = server_user.trim();
    if server.is_empty() {
        return MatchResult::NoMatch;
    }

    // ── Rule 1: exact match ────────────────────────────
    let exact: Vec<usize> = local_users
        .iter()
        .enumerate()
        .filter(|(_, user)| user.username.trim() == server)
        .map(|(idx, _)| idx)
        .collect();
    match exact.len() {
        0 => {}
        1 => return MatchResult::Exact(exact[0]),
        _ => return MatchResult::Ambiguous(exact),
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

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e.without_url()))?;

    parse_online_user_info(&body, content_type.as_deref())
}

fn parse_online_user_info(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<Option<OnlineUserInfo>, String> {
    let body =
        crate::core::srun::decode_body(bytes, content_type).map_err(|error| error.to_string())?;
    let json_str = crate::core::jsonp::strip_jsonp(&body)
        .map_err(|_| "Invalid rad_user_info JSONP".to_string())?;

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

pub(crate) fn status_query_ip_from_interfaces(
    s: &crate::service::AppState,
    interfaces: &[(String, std::net::IpAddr)],
) -> Option<String> {
    let previous = best_status_query_ip(s);
    let is_local = |ip: &str| {
        ip.parse::<std::net::Ipv4Addr>().is_ok_and(|addr| {
            interfaces
                .iter()
                .any(|(_, local)| *local == std::net::IpAddr::V4(addr))
        })
    };
    if interfaces.is_empty() {
        return previous;
    }

    // Respect an active account's interface binding even if its former IP has
    // moved to another adapter. Do not change the displayed IP before confirmation.
    for state in [LoginState::Online, LoginState::PendingConfirm] {
        for (idx, status) in s.user_statuses.iter().enumerate() {
            if status.state == state {
                if let Some(name) = s
                    .config
                    .users
                    .get(idx)
                    .and_then(|user| user.if_name.as_deref())
                {
                    if let Some(ip) = crate::core::utils::ipv4_by_if_name_preferring(
                        name,
                        interfaces,
                        Some(&status.current_ip),
                    ) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    // A previously active account keeps its binding after offline confirmation.
    for &idx in &s.reconnect_targets {
        if let Some(name) = s
            .config
            .users
            .get(idx)
            .and_then(|user| user.if_name.as_deref())
        {
            let preferred = s
                .user_statuses
                .get(idx)
                .map(|status| status.current_ip.as_str())
                .filter(|ip| !ip.is_empty())
                .or(previous.as_deref());
            if let Some(ip) =
                crate::core::utils::ipv4_by_if_name_preferring(name, interfaces, preferred)
            {
                return Some(ip);
            }
        }
    }
    // Before the first login, query through the same account binding that the
    // startup one-click login will try, rather than an unrelated global adapter.
    if s.reconnect_targets.is_empty()
        && !s.user_statuses.iter().any(|status| {
            matches!(
                status.state,
                LoginState::Online | LoginState::PendingConfirm
            )
        })
    {
        if let Some(user) = s.config.users.first() {
            if let Some(ip) = user
                .if_name
                .as_deref()
                .and_then(|name| crate::core::utils::ipv4_by_if_name(name, interfaces))
            {
                return Some(ip);
            }
            if let Some(ip) = user_ip::configured_static_ip(user).filter(|ip| is_local(ip)) {
                return Some(ip);
            }
        }
    }
    if previous.as_deref().is_some_and(is_local) {
        return previous;
    }
    if let Some(ip) = s.campus_ip.as_deref().filter(|ip| is_local(ip)) {
        return Some(ip.into());
    }
    crate::service::detection::campus_ip_candidates_from_interfaces(interfaces)
        .first()
        .map(|(_, ip)| ip.clone())
        .or(previous)
}

/// Preserve the active account before the authoritative offline result demotes it.
fn apply_server_offline(s: &mut crate::service::AppState) {
    let active: Vec<usize> = s
        .user_statuses
        .iter()
        .enumerate()
        .filter(|(_, status)| {
            matches!(
                status.state,
                LoginState::Online | LoginState::PendingConfirm
            )
        })
        .map(|(idx, _)| idx)
        .collect();
    if !active.is_empty() {
        s.reconnect_targets = active;
    }
    s.auth_server = AuthServerStatus::Reachable;
    s.campus_auth = CampusAuthStatus::NotLoggedIn;
    s.online_info = None;
    s.online_info_fail_count = 0;
    s.online_info_stale = false;
    for status in &mut s.user_statuses {
        if matches!(
            status.state,
            LoginState::Online | LoginState::PendingConfirm
        ) {
            status.state = LoginState::Error;
            status.last_error = "Server reports no user logged in".into();
        }
    }
}

struct StatusQuery {
    server: String,
    ip: Option<String>,
    context_ip: Option<String>,
    campus_ip: Option<String>,
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
            context_ip: best_status_query_ip(s),
            campus_ip: s.campus_ip.clone(),
            auth_generation: s.auth_generation,
            query_generation: s.online_query_generation,
        })
    }

    fn is_current(&self, s: &crate::service::AppState) -> bool {
        !s.authentication_busy()
            && self.auth_generation == s.auth_generation
            && self.query_generation == s.online_query_generation
            && self.server == s.config.server
            && self.campus_ip == s.campus_ip
            && self.context_ip == best_status_query_ip(s)
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

impl StatusQueryGuard {
    fn begin(state: &SharedState, expected_generations: Option<(u64, u64)>) -> Option<Self> {
        let query = {
            let mut s = state.lock().unwrap();
            if expected_generations.is_some_and(|(auth, query)| {
                s.auth_generation != auth || s.online_query_generation != query
            }) {
                return None;
            }
            StatusQuery::begin(&mut s)?
        };
        let guard = Self {
            state: state.clone(),
            query,
        };
        crate::service::request_ui_repaint();
        Some(guard)
    }

    fn use_interfaces(&mut self, interfaces: &[(String, std::net::IpAddr)], fresh: bool) -> bool {
        let mut s = self.state.lock().unwrap();
        if !self.query.is_current(&s) {
            return false;
        }
        if fresh {
            s.network_interfaces = Some(interfaces.to_vec());
            s.campus_ip = detect_campus_ip_from_interfaces(interfaces);
            self.query.campus_ip = s.campus_ip.clone();
            self.query.context_ip = best_status_query_ip(&s);
        }
        if !interfaces.iter().any(|(_, ip)| ip.is_ipv4()) {
            // An empty/IPv6-only snapshot cannot validate the old IPv4's
            // offline response. Preserve the account and wait for an address.
            s.campus_auth = CampusAuthStatus::Unknown;
            s.online_info_stale = true;
            s.ipv4_internet = if s.config.enable_ipv4_internet_probe {
                crate::service::Ipv4InternetStatus::ProbeFailed
            } else {
                crate::service::Ipv4InternetStatus::Disabled
            };
            s.add_log(
                "[WARN] No local IPv4 available; waiting before status checks or reconnect".into(),
            );
            return false;
        }
        self.query.ip = status_query_ip_from_interfaces(&s, interfaces);
        true
    }
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
    sync_online_state_collecting(state, crate::core::utils::get_network_interfaces_async()).await;
}

async fn sync_online_state_collecting(
    state: &SharedState,
    collect: impl std::future::Future<Output = Vec<(String, std::net::IpAddr)>>,
) {
    let Some(guard) = StatusQueryGuard::begin(state, None) else {
        return;
    };
    // Enumerate outside AppState locks; DHCP can invalidate a last-seen session IP.
    let interfaces = collect.await;
    sync_online_state_claimed(guard, &interfaces, false).await;
}

/// The monitor/startup already read the OS address table; reuse that same
/// snapshot while preserving the usual authentication/query ownership checks.
/// Returns false if the snapshot's original context can no longer be claimed.
pub(crate) async fn sync_online_state_from_interfaces(
    state: &SharedState,
    interfaces: &[(String, std::net::IpAddr)],
    expected_auth_generation: u64,
    expected_query_generation: u64,
    from_cache: bool,
) -> bool {
    let Some(guard) = StatusQueryGuard::begin(
        state,
        Some((expected_auth_generation, expected_query_generation)),
    ) else {
        return false;
    };
    sync_online_state_claimed(guard, interfaces, from_cache).await;
    true
}

async fn sync_online_state_claimed(
    guard: StatusQueryGuard,
    interfaces: &[(String, std::net::IpAddr)],
    from_cache: bool,
) {
    sync_online_state_claimed_with_io(
        guard,
        interfaces,
        from_cache,
        crate::core::utils::get_network_interfaces_async,
        |server, ip| async move { fetch_online_user_info(&server, ip.as_deref()).await },
    )
    .await;
}

async fn sync_online_state_claimed_with_io<Read, ReadFuture, Fetch, FetchFuture>(
    mut guard: StatusQueryGuard,
    interfaces: &[(String, std::net::IpAddr)],
    from_cache: bool,
    read: Read,
    fetch: Fetch,
) where
    Read: FnOnce() -> ReadFuture,
    ReadFuture: std::future::Future<Output = Vec<(String, std::net::IpAddr)>>,
    Fetch: Fn(String, Option<String>) -> FetchFuture,
    FetchFuture: std::future::Future<Output = Result<Option<OnlineUserInfo>, String>>,
{
    if !guard.use_interfaces(interfaces, !from_cache) {
        return;
    }
    let first_ip = guard.query.ip.clone();
    let mut result = fetch(guard.query.server.clone(), first_ip.clone()).await;
    let refresh_cached = if from_cache {
        let s = guard.state.lock().unwrap();
        if !guard.query.is_current(&s) {
            return;
        }
        match (&result, s.current_online_info()) {
            (Ok(Some(next)), Some(previous)) => {
                // A different session can mean the old address moved to another
                // adapter. Preserve compatible base/suffix account matching.
                let same_account = previous.user_name.trim() == next.user_name.trim()
                    || confirmed_online_user_idx(Some(previous), &s.config.users).is_some_and(
                        |idx| confirmed_online_user_idx(Some(next), &s.config.users) == Some(idx),
                    );
                !same_account || previous.online_ip != next.online_ip
            }
            _ => true,
        }
    } else {
        false
    };
    if refresh_cached {
        let fresh_interfaces = read().await;
        if !guard.use_interfaces(&fresh_interfaces, true) {
            return;
        }
        if guard.query.ip != first_ip {
            // The old address may now belong to another adapter. Confirm
            // through the refreshed binding before demoting or reconnecting.
            result = fetch(guard.query.server.clone(), guard.query.ip.clone()).await;
        }
    }
    let state = &guard.state;
    let query = &guard.query;
    let (server, query_ip) = (&query.server, &query.ip);

    match result {
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
            apply_server_offline(&mut s);
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
                        let auth_status = check_auth_status(server, query_ip.as_deref()).await;
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
        let (startup_auth_generation, startup_query_generation) = {
            let s = state.lock().unwrap();
            (s.auth_generation, s.online_query_generation)
        };
        let interfaces = crate::core::utils::get_network_interfaces_async().await;
        {
            let ip = detect_campus_ip_from_interfaces(&interfaces);
            let mut s = state.lock().unwrap();
            if s.auth_generation == startup_auth_generation
                && s.online_query_generation == startup_query_generation
                && !s.authentication_busy()
                && !s.online_query_busy
            {
                s.campus_ip = ip;
            }
        }
        crate::service::request_ui_repaint();

        // ── Phase 3: Sync online state from server ─────
        let startup_synced = sync_online_state_from_interfaces(
            &state,
            &interfaces,
            startup_auth_generation,
            startup_query_generation,
            false,
        )
        .await;

        // ── Phase 4: Conditional auto-login ────────────
        let (
            auto_reconnect,
            should_login,
            has_online,
            campus_auth,
            generation,
            first_user,
            startup_current,
        ) = {
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
                startup_synced
                    && s.auth_generation == startup_auth_generation
                    && s.online_query_generation == startup_query_generation.wrapping_add(1)
                    && !s.authentication_busy()
                    && !s.online_query_busy,
            )
        };
        if startup_current
            && should_auto_login(auto_reconnect, has_online, should_login, &campus_auth)
        {
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
        } else if startup_current
            && auto_reconnect
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
mod cache_tests;

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
    fn confirmed_disconnect_keeps_the_previous_account_first_for_reconnect() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        s.config.users = vec![make_user("test-first"), make_user("test-active")];
        s.ensure_statuses();
        s.user_statuses[1].state = LoginState::Online;
        apply_server_offline(&mut s);
        assert_eq!(s.reconnect_targets, vec![1]);
        assert_eq!(s.user_statuses[1].state, LoginState::Error);
        assert!(crate::service::monitor::reconnect_needed(&s, true));
        apply_server_offline(&mut s);
        assert_eq!(s.reconnect_targets, vec![1]);
        s.suppress_auto_reconnect = true;
        assert!(!crate::service::monitor::reconnect_needed(&s, true));
    }

    #[test]
    fn cold_start_queries_follow_the_account_binding_before_the_global_ip() {
        let interfaces = vec![
            ("test-other".into(), "10.0.0.99".parse().unwrap()),
            ("test-campus".into(), "10.0.0.3".parse().unwrap()),
            ("test-tun".into(), "198.18.0.1".parse().unwrap()),
        ];
        for bound in [true, false] {
            let mut s = make_app_state();
            let mut user = make_user("test-startup-user");
            user.if_name = bound.then(|| "test-campus".into());
            user.ip = Some(if bound { "10.0.0.99" } else { "10.0.0.3" }.into());
            s.config.users.push(user);
            s.ensure_statuses();
            s.campus_ip = Some("10.0.0.99".into());
            assert_eq!(s.user_statuses[0].state, LoginState::LoggedOut);
            assert!(s.reconnect_targets.is_empty());
            assert_eq!(
                status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
                Some("10.0.0.3")
            );
        }
    }

    #[test]
    fn a_changed_dhcp_address_does_not_leave_status_queries_bound_to_the_old_ip() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        let mut user = make_user("test-dhcp-user");
        user.if_name = Some("test-campus".into());
        s.config.users.push(user);
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.2".into();
        s.campus_ip = Some("10.0.0.99".into());
        let interfaces = vec![
            ("test-other".into(), "10.0.0.99".parse().unwrap()),
            ("test-campus".into(), "10.0.0.3".parse().unwrap()),
        ];
        assert_eq!(
            status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
            Some("10.0.0.3")
        );
        let mut query = StatusQuery::begin(&mut s).unwrap();
        query.ip = status_query_ip_from_interfaces(&s, &interfaces);
        assert!(query.is_current(&s));
        assert_eq!(s.user_statuses[0].current_ip, "10.0.0.2");
        s.invalidate_auth_context();
        assert!(!query.is_current(&s));
    }

    #[test]
    fn status_queries_keep_a_valid_session_ip_and_do_not_guess_without_interfaces() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        s.config.users.push(make_user("test-user"));
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.2".into();
        s.campus_ip = Some("10.0.0.3".into());
        let interfaces = vec![("test-campus".into(), "10.0.0.2".parse().unwrap())];
        assert_eq!(
            status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
            Some("10.0.0.2")
        );
        assert_eq!(
            status_query_ip_from_interfaces(&s, &[]).as_deref(),
            Some("10.0.0.2")
        );
    }

    #[test]
    fn a_bound_account_follows_its_interface_when_the_old_ip_moves_to_another_adapter() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        let mut user = make_user("test-bound-user");
        user.if_name = Some("test-campus".into());
        s.config.users.push(user);
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.2".into();
        let interfaces = vec![
            ("test-other".into(), "10.0.0.2".parse().unwrap()),
            ("test-campus".into(), "10.0.0.3".parse().unwrap()),
        ];
        assert_eq!(
            status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
            Some("10.0.0.3")
        );
    }

    #[test]
    fn a_reconnect_target_follows_its_interface_after_the_old_ip_moves() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        let mut user = make_user("test-bound-user");
        user.if_name = Some("test-campus".into());
        user.ip = Some("10.0.0.2".into());
        s.config.users.push(user);
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::Online;
        s.user_statuses[0].current_ip = "10.0.0.2".into();
        apply_server_offline(&mut s);
        assert_eq!(s.user_statuses[0].state, LoginState::Error);
        let interfaces = vec![
            ("test-other".into(), "10.0.0.2".parse().unwrap()),
            ("test-campus".into(), "10.0.0.3".parse().unwrap()),
        ];
        assert_eq!(
            status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
            Some("10.0.0.3")
        );
    }

    #[test]
    fn bound_queries_preserve_the_session_ip_on_a_multi_address_interface() {
        let interfaces = vec![
            ("test-campus".into(), "10.0.0.3".parse().unwrap()),
            ("test-campus".into(), "10.0.0.2".parse().unwrap()),
        ];
        for binding in ["test-campus", "campus"] {
            for state in [LoginState::Online, LoginState::PendingConfirm] {
                let mut s =
                    crate::service::AppState::new(crate::service::config::AppConfig::default());
                let mut user = make_user("test-bound-user");
                user.if_name = Some(binding.into());
                user.ip = Some("10.0.0.99".into());
                s.config.users.push(user);
                s.ensure_statuses();
                s.user_statuses[0].state = state;
                s.user_statuses[0].current_ip = "10.0.0.2".into();
                assert_eq!(
                    status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
                    Some("10.0.0.2")
                );
                apply_server_offline(&mut s);
                assert_eq!(
                    status_query_ip_from_interfaces(&s, &interfaces).as_deref(),
                    Some("10.0.0.2")
                );
            }
        }
    }

    #[test]
    fn duplicate_exact_names_are_ambiguous_instead_of_confirming_the_first_user() {
        let users = vec![make_user("test-user"), make_user(" test-user ")];
        let result = match_account("test-user", &users);
        assert_eq!(result, MatchResult::Ambiguous(vec![0, 1]));
        let info = OnlineUserInfo {
            error: "ok".into(),
            user_name: "test-user".into(),
            ..Default::default()
        };
        assert_eq!(confirmed_online_user_idx(Some(&info), &users), None);
    }

    #[test]
    fn malformed_status_is_unknown_instead_of_offline() {
        for body in [r#"{}"#, r#"{"error":"ip_error"}"#, r#"{"error":"ok"}"#] {
            let response = format!("sdu({body})");
            assert!(
                parse_online_user_info(response.as_bytes(), None).is_err(),
                "misclassified response: {body}"
            );
        }
    }

    #[test]
    fn malformed_status_diagnostics_do_not_include_response_payloads() {
        for body in [
            "test-sensitive-sentinel",
            "sdu({\"private\":\"test-sensitive-sentinel\"}",
        ] {
            let error = parse_online_user_info(body.as_bytes(), None).unwrap_err();
            assert!(!error.contains("test-sensitive-sentinel"));
        }
    }

    #[test]
    fn explicit_offline_status_and_online_gbk_are_supported() {
        for error in ["not_online", "not_online_error"] {
            let body = format!(r#"sdu({{"error":"{error}"}})"#);
            assert!(parse_online_user_info(body.as_bytes(), None)
                .unwrap()
                .is_none());
        }
        let body = r#"sdu({"error":"ok","user_name":"测试账号","online_ip":"10.0.0.1"})"#;
        let (bytes, _, had_errors) = encoding_rs::GBK.encode(body);
        assert!(!had_errors);
        let info = parse_online_user_info(&bytes, None).unwrap().unwrap();
        assert_eq!(info.user_name, "测试账号");
    }

    #[test]
    fn online_status_uses_declared_charset_without_garbling_display_fields() {
        let body = r#"sdu({"error":"ok","user_name":"preview-user","products_name":"忙"})"#;
        let (bytes, _, errors) = encoding_rs::GBK.encode(body);
        assert!(!errors);
        let info = parse_online_user_info(&bytes, Some("text/javascript; charset=gbk"))
            .unwrap()
            .unwrap();
        assert_eq!(info.products_name, "忙");
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

    #[tokio::test]
    async fn slow_interface_collection_is_exclusive_and_cancellation_releases_it() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        };

        let state = Arc::new(Mutex::new(make_app_state()));
        let collections = AtomicUsize::new(0);
        let mut refresh = Box::pin(sync_online_state_collecting(&state, async {
            collections.fetch_add(1, Ordering::SeqCst);
            // No OS/network calls: pause inside the synthetic interface query.
            std::future::pending().await
        }));
        tokio::select! {
            biased;
            _ = &mut refresh => panic!("synthetic collection should still be pending"),
            _ = std::future::ready(()) => {}
        }
        assert!(
            state.lock().unwrap().online_query_busy,
            "refresh must be claimed before local interface collection starts"
        );
        sync_online_state_collecting(&state, async {
            collections.fetch_add(1, Ordering::SeqCst);
            panic!("a duplicate refresh must not poll its interface collector");
        })
        .await;
        assert_eq!(collections.load(Ordering::SeqCst), 1);
        drop(refresh);
        let s = state.lock().unwrap();
        assert!(!s.online_query_busy);
        assert_eq!(s.auth_generation, 0);
        assert_eq!(s.campus_auth, CampusAuthStatus::Unknown);
    }

    #[test]
    fn an_old_interface_snapshot_cannot_claim_a_newer_authentication_or_query_context() {
        use std::sync::{Arc, Mutex};
        for auth_changed in [true, false] {
            let state = Arc::new(Mutex::new(make_app_state()));
            let origin = {
                let mut s = state.lock().unwrap();
                s.config.users.push(make_user("test-snapshot"));
                s.ensure_statuses();
                (s.auth_generation, s.online_query_generation)
            };
            // Simulate a slow A-address snapshot returning after a newer
            // login or completed refresh has already established address B.
            {
                let mut s = state.lock().unwrap();
                if auth_changed {
                    s.invalidate_auth_context();
                } else {
                    s.online_query_generation = s.online_query_generation.wrapping_add(1);
                }
                s.campus_ip = Some("10.0.0.4".into());
                s.user_statuses[0].current_ip = "10.0.0.4".into();
                s.user_statuses[0].state = LoginState::PendingConfirm;
            }
            let before_query = state.lock().unwrap().online_query_generation;
            assert!(StatusQueryGuard::begin(&state, Some(origin)).is_none());
            let s = state.lock().unwrap();
            assert_eq!(s.online_query_generation, before_query);
            assert!(!s.online_query_busy);
            assert_eq!(s.user_statuses[0].state, LoginState::PendingConfirm);
            assert_eq!(s.user_statuses[0].current_ip, "10.0.0.4");
        }

        let state = Arc::new(Mutex::new(make_app_state()));
        let origin = {
            let s = state.lock().unwrap();
            (s.auth_generation, s.online_query_generation)
        };
        let guard = StatusQueryGuard::begin(&state, Some(origin)).unwrap();
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
