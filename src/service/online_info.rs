use std::time::Duration;

use serde::Deserialize;

use crate::service::detection::{check_auth_server, check_auth_status, detect_campus_ip};
use crate::service::{AuthServerStatus, CampusAuthStatus, LoginState, SharedState};

/// Parsed from /cgi-bin/rad_user_info?callback=sdu JSONP response.
/// All fields have defaults — the API may change over srun versions.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OnlineUserInfo {
    /// "ok" means logged in; any other value means not logged in or error.
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

/// Safely truncate a string to at most `max_chars` characters, on a
/// UTF-8 character boundary. Does not panic for any input.
fn safe_truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

/// Strip a JSONP wrapper like `sdu({...})` or ` sdu({...}); ` from `body`,
/// returning the inner JSON string. Handles whitespace and optional trailing
/// semicolon. Returns `Err(description)` on malformed input; the description
/// uses char-safe truncation and never panics.
fn strip_jsonp(body: &str) -> Result<&str, String> {
    let trimmed = body.trim();

    let after_prefix = trimmed.strip_prefix("sdu(").ok_or_else(|| {
        format!(
            "Unexpected JSONP format (first 80 chars): {}",
            safe_truncate(trimmed, 80)
        )
    })?;

    let inner = after_prefix
        .strip_suffix(')')
        .or_else(|| after_prefix.strip_suffix(");"))
        .ok_or_else(|| {
            format!(
                "JSONP missing closing ')' (first 80 chars): {}",
                safe_truncate(trimmed, 80)
            )
        })?;

    Ok(inner.trim())
}

/// Fetch online user info from the auth server's rad_user_info endpoint.
///
/// Returns:
/// - `Ok(Some(info))` — successfully fetched and `error == "ok"` (logged in)
/// - `Ok(None)` — request succeeded but `error != "ok"` (not logged in)
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
        .unwrap()
        .as_secs()
        .to_string();

    tracing::info!(
        "[OnlineInfo] Querying: url={} campus_ipv4={:?}",
        url,
        campus_ipv4
    );

    let resp = client
        .get(&url)
        .query(&[("callback", "sdu"), ("_", &ts)])
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let json_str = strip_jsonp(&body)?;

    let info: OnlineUserInfo =
        serde_json::from_str(json_str).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    if info.error == "ok" {
        tracing::info!(
            "[OnlineInfo] User online: user_name={} ip={} sum_seconds={}",
            info.user_name,
            info.online_ip,
            info.sum_seconds
        );
        Ok(Some(info))
    } else {
        tracing::info!("[OnlineInfo] Not logged in: error={}", info.error);
        Ok(None)
    }
}

/// Query rad_user_info and update AppState accordingly.
/// Called at startup and periodically by the monitor.
pub async fn sync_online_state(state: &SharedState) {
    let (server, query_ip) = {
        let s = state.lock().unwrap();
        // Prefer the IP of a currently confirmed-online user, then a
        // PendingConfirm user, then the global auto-detected campus IP.
        let best_ip = s
            .user_statuses
            .iter()
            .find(|us| us.state == LoginState::Online)
            .or_else(|| {
                s.user_statuses
                    .iter()
                    .find(|us| us.state == LoginState::PendingConfirm)
            })
            .and_then(|us| {
                if !us.current_ip.is_empty() {
                    Some(us.current_ip.clone())
                } else {
                    None
                }
            })
            .or_else(|| s.campus_ip.clone());
        (s.config.server.clone(), best_ip)
    };

    match fetch_online_user_info(&server, query_ip.as_deref()).await {
        Ok(Some(info)) => {
            let mut s = state.lock().unwrap();
            s.auth_server = AuthServerStatus::Reachable;
            s.campus_auth = CampusAuthStatus::LoggedIn;
            s.online_info = Some(info.clone());
            s.online_info_fail_count = 0;
            s.online_info_stale = false;

            let match_result = match_account(&info.user_name, &s.config.users);
            // Reset all users that were Online or PendingConfirm — the server
            // is authoritative, so anything stale must be corrected.
            for (idx, us) in s.user_statuses.iter_mut().enumerate() {
                let is_matched = match &match_result {
                    MatchResult::Exact(i) | MatchResult::UniqueBase(i) => *i == idx,
                    MatchResult::Ambiguous(indices) => indices.contains(&idx),
                    MatchResult::NoMatch => false,
                };
                if is_matched {
                    us.state = LoginState::Online;
                    us.current_ip = info.online_ip.clone();
                    us.last_error.clear();
                } else if us.state == LoginState::Online || us.state == LoginState::PendingConfirm {
                    us.state = LoginState::Error;
                    us.last_error = format!("Another account is online: {}", info.user_name);
                }
            }
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
            crate::service::request_ui_repaint();
        }

        Ok(None) => {
            let mut s = state.lock().unwrap();
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
            crate::service::request_ui_repaint();
        }

        Err(msg) => {
            let (_fail_count, degraded) = {
                let mut s = state.lock().unwrap();
                s.online_info_fail_count += 1;
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
                let auth_server = check_auth_server(&server, query_ip.as_deref()).await;
                let reachable = auth_server == AuthServerStatus::Reachable;
                let probe_enabled = {
                    let s = state.lock().unwrap();
                    s.config.enable_ipv4_internet_probe
                };
                {
                    let mut s = state.lock().unwrap();
                    s.auth_server = auth_server;
                    if !reachable {
                        s.campus_auth = CampusAuthStatus::Unknown;
                    }
                }
                if reachable {
                    if probe_enabled {
                        let auth_status = check_auth_status(query_ip.as_deref()).await;
                        let mut s = state.lock().unwrap();
                        s.campus_auth = auth_status;
                    } else {
                        // IPv4 internet probe disabled — do NOT call check_auth_status()
                        // which would access http://www.baidu.com
                        let mut s = state.lock().unwrap();
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
pub fn spawn_startup_tasks(state: SharedState) {
    tokio::spawn(async move {
        // ── Phase 1: Version check ──────────────────────
        {
            let mut s = state.lock().unwrap();
            s.update_status = crate::service::update::UpdateStatus::Checking;
            s.add_log("[INFO] Checking for updates...".to_string());
        }
        crate::service::request_ui_repaint();

        match crate::service::update::check_update().await {
            Ok(Some((latest, release_url, download_url))) => {
                let mut s = state.lock().unwrap();
                s.add_log(format!("[INFO] New version available: {}", latest));
                s.update_status = crate::service::update::UpdateStatus::Available {
                    latest,
                    release_url,
                    download_url,
                };
            }
            Ok(None) => {
                let mut s = state.lock().unwrap();
                s.update_status = crate::service::update::UpdateStatus::UpToDate;
            }
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.add_log(format!("[WARN] Version check failed: {}", e));
                s.update_status = crate::service::update::UpdateStatus::Failed(e);
            }
        }
        crate::service::request_ui_repaint();

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
        let (auto_reconnect, should_login, has_online) = {
            let s = state.lock().unwrap();
            let has_online = s
                .user_statuses
                .iter()
                .any(|us| us.state == LoginState::Online || us.state == LoginState::PendingConfirm);
            (s.config.auto_reconnect, s.config.users.len(), has_online)
        };

        if auto_reconnect && !has_online && should_login > 0 {
            let campus_auth = {
                let s = state.lock().unwrap();
                s.campus_auth.clone()
            };
            if campus_auth != CampusAuthStatus::LoggedIn {
                tracing::info!(
                    "[Startup] Auto-reconnect enabled, not logged in — starting one-click login"
                );
                {
                    let mut s = state.lock().unwrap();
                    s.suppress_auto_reconnect = false;
                    s.add_log("[INFO] Auto-login on startup...".to_string());
                }
                crate::service::request_ui_repaint();
                crate::service::auth::do_one_click_login(state.clone()).await;
                // Re-sync after login attempt
                sync_online_state(&state).await;
            }
        }

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

    // ── match_account tests ───────────────────────────────

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

    // ── strip_jsonp tests ─────────────────────────────────

    #[test]
    fn strip_jsonp_normal() {
        assert_eq!(strip_jsonp("sdu({\"a\":1})").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn strip_jsonp_with_semicolon() {
        assert_eq!(strip_jsonp("sdu({\"a\":1});").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn strip_jsonp_whitespace() {
        assert_eq!(strip_jsonp("  sdu({\"a\":1})  ").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn strip_jsonp_whitespace_and_semicolon() {
        assert_eq!(strip_jsonp(" sdu(  {\"a\":1}  ); ").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn strip_jsonp_malformed_no_prefix() {
        assert!(strip_jsonp("not_jsonp").is_err());
    }

    #[test]
    fn strip_jsonp_malformed_no_suffix() {
        assert!(strip_jsonp("sdu({\"a\":1}").is_err());
    }

    // ── safe_truncate tests ───────────────────────────────

    #[test]
    fn safe_truncate_short() {
        assert_eq!(safe_truncate("hello", 80), "hello");
    }

    #[test]
    fn safe_truncate_exact_boundary() {
        assert_eq!(safe_truncate("abc", 3), "abc");
    }

    #[test]
    fn safe_truncate_multibyte_safe() {
        // 3-byte Chinese chars: 你好世界 = 12 bytes, 4 chars
        let s = "你好世界";
        assert_eq!(safe_truncate(s, 2).chars().count(), 2);
        // Must not panic
        let _ = safe_truncate(s, 1);
        let _ = safe_truncate(s, 3);
    }

    #[test]
    fn safe_truncate_empty() {
        assert_eq!(safe_truncate("", 80), "");
    }
}
