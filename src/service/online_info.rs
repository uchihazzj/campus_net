use std::net::Ipv4Addr;
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

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            builder = builder.local_address(std::net::IpAddr::V4(addr));
        }
    }

    let client = builder
        .build()
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

    // Strip JSONP wrapper: sdu({...}) → {...}
    let json_str = body
        .strip_prefix("sdu(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "Unexpected JSONP format (first 80 chars): {}",
                &body[..body.len().min(80)]
            )
        })?;

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
    let (server, campus_ip) = {
        let s = state.lock().unwrap();
        (s.config.server.clone(), s.campus_ip.clone())
    };

    match fetch_online_user_info(&server, campus_ip.as_deref()).await {
        Ok(Some(info)) => {
            let mut s = state.lock().unwrap();
            s.auth_server = AuthServerStatus::Reachable;
            s.campus_auth = CampusAuthStatus::LoggedIn;
            s.online_info = Some(info.clone());
            s.online_info_fail_count = 0;

            // Match online user_name to local configured users.
            // Collect usernames first to avoid borrowing s.config and
            // s.user_statuses simultaneously.
            let usernames: Vec<String> =
                s.config.users.iter().map(|u| u.username.clone()).collect();
            let mut matched = false;
            for (idx, uname) in usernames.iter().enumerate() {
                if let Some(us) = s.user_statuses.get_mut(idx) {
                    if *uname == info.user_name {
                        us.state = LoginState::Online;
                        us.current_ip = info.online_ip.clone();
                        us.last_error.clear();
                        matched = true;
                    } else if us.state == LoginState::Online {
                        us.state = LoginState::Error;
                        us.last_error = format!("Another account is online: {}", info.user_name);
                    }
                }
            }
            if matched {
                s.add_log(format!(
                    "[OK] {} confirmed online by server, IP={}",
                    info.user_name, info.online_ip
                ));
            } else {
                s.add_log(format!(
                    "[WARN] Server reports online user {} (IP={}), not in local config",
                    info.user_name, info.online_ip
                ));
            }
            crate::service::request_ui_repaint();
        }

        Ok(None) => {
            let mut s = state.lock().unwrap();
            s.auth_server = AuthServerStatus::Reachable;
            s.campus_auth = CampusAuthStatus::NotLoggedIn;
            s.online_info = None;
            s.online_info_fail_count = 0;

            // Invalidate users that were marked Online
            for us in &mut s.user_statuses {
                if us.state == LoginState::Online {
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
                let auth_server = check_auth_server(&server, campus_ip.as_deref()).await;
                let reachable = auth_server == AuthServerStatus::Reachable;
                {
                    let mut s = state.lock().unwrap();
                    s.auth_server = auth_server;
                    if !reachable {
                        s.campus_auth = CampusAuthStatus::Unknown;
                    }
                }
                if reachable {
                    let auth_status = check_auth_status(campus_ip.as_deref()).await;
                    let mut s = state.lock().unwrap();
                    s.campus_auth = auth_status;
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
                .any(|us| us.state == LoginState::Online);
            (s.config.auto_reconnect, s.config.users.len(), has_online)
        };

        if auto_reconnect && !has_online && should_login > 0 {
            let campus_auth = {
                let s = state.lock().unwrap();
                s.campus_auth.clone()
            };
            if campus_auth == CampusAuthStatus::NotLoggedIn {
                tracing::info!(
                    "[Startup] Auto-reconnect enabled, not logged in — starting one-click login"
                );
                {
                    let mut s = state.lock().unwrap();
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
