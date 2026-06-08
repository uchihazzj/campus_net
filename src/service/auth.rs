use std::time::Duration;

use crate::core::srun::SrunClient;
use crate::platform::secure_store;
use crate::service::online_info::sync_online_state;
use crate::service::user_ip;
use crate::service::{LoginState, SharedState};

pub async fn do_login(state: SharedState, user_idx: usize) {
    let (server, username, user, detect_ip, strict_bind, double_stack) = {
        let s = state.lock().unwrap();
        let cfg = &s.config;
        if user_idx >= cfg.users.len() {
            return;
        }
        let user = &cfg.users[user_idx];
        (
            cfg.server.clone(),
            user.username.clone(),
            user.clone(),
            cfg.detect_ip,
            cfg.strict_bind,
            cfg.double_stack,
        )
    };

    let ip = user_ip::resolve_login_ip(&user);
    let test_before_login = false;

    // Guard: block login if a different local account is already confirmed online
    {
        let mut s = state.lock().unwrap();
        if let Some(online_idx) = crate::service::online_info::confirmed_online_user_idx(
            s.online_info.as_ref(),
            &s.config.users,
        ) {
            if online_idx != user_idx && user_idx < s.config.users.len() {
                let target_uname = s.config.users[user_idx].username.clone();
                let online_uname = s.config.users[online_idx].username.clone();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = format!(
                    "Another account is already online: {}. Please logout first before logging into this account.",
                    online_uname
                );
                s.add_log(format!(
                    "[WARN] {}: login blocked because {} is already online",
                    target_uname, online_uname
                ));
                crate::service::request_ui_repaint();
                return;
            }
        }
    }

    let encrypted_password = {
        let s = state.lock().unwrap();
        match s.config.users.get(user_idx) {
            Some(user) => user.encrypted_password.clone(),
            None => return,
        }
    };

    let password = match secure_store::decrypt_password(&encrypted_password) {
        Ok(p) => p,
        Err(e) => {
            let mut s = state.lock().unwrap();
            if user_idx < s.config.users.len() {
                let uname = s.config.users[user_idx].username.clone();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = format!("Password decrypt failed: {}", e);
                s.add_log(format!("[ERROR] {}: Failed to decrypt password", uname));
            }
            crate::service::request_ui_repaint();
            return;
        }
    };

    {
        let mut s = state.lock().unwrap();
        if user_idx >= s.config.users.len() {
            return;
        }
        let uname = s.config.users[user_idx].username.clone();
        s.user_statuses[user_idx].state = LoginState::LoggingIn;
        s.user_statuses[user_idx].last_error.clear();
        s.suppress_auto_reconnect = false;
        s.add_log(format!("[INFO] {}: Logging in...", uname));
    }
    crate::service::request_ui_repaint();

    let mut client = SrunClient::new(&server, &username, &password, &ip)
        .set_detect_ip(detect_ip)
        .set_strict_bind(strict_bind)
        .set_double_stack(double_stack)
        .set_test_before_login(test_before_login);

    {
        let s = state.lock().unwrap();
        let cfg = &s.config;
        client = client
            .set_n(cfg.n)
            .set_type(cfg.utype)
            .set_acid(cfg.acid)
            .set_os(&cfg.os)
            .set_name(&cfg.name)
            .set_retry_delay(cfg.retry_delay)
            .set_retry_times(cfg.retry_times);
    }

    match client.login().await {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if user_idx < s.config.users.len() {
                    let uname = s.config.users[user_idx].username.clone();
                    let ip = client.client_ip.clone();
                    // Portal login succeeded but server (rad_user_info) has not
                    // yet confirmed. Do NOT mark as Online here.
                    s.user_statuses[user_idx].state = LoginState::PendingConfirm;
                    s.user_statuses[user_idx].current_ip = ip.clone();
                    s.add_log(format!(
                        "[OK] {}: Login request succeeded (portal), IP={}, waiting for server confirmation",
                        uname, ip
                    ));
                    // Clear stale online_info that may belong to a different user.
                    s.online_info = None;
                    s.online_info_fail_count = 0;
                    // online_info_stale is NOT cleared here — only rad_user_info
                    // success can clear it (in sync_online_state).
                }
            }
            // Refresh online_info to confirm the session and populate details.
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                sync_online_state(&st).await;
            });
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            if user_idx < s.config.users.len() {
                let uname = s.config.users[user_idx].username.clone();
                let err = e.to_string();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = err.clone();
                s.add_log(format!("[ERROR] {}: Login failed - {}", uname, err));
            }
        }
    }
    crate::service::request_ui_repaint();
}

pub async fn do_logout(state: SharedState, user_idx: usize) {
    let (server, username, user, status_ip, detect_ip, strict_bind, acid) = {
        let s = state.lock().unwrap();
        let cfg = &s.config;
        if user_idx >= cfg.users.len() {
            return;
        }
        let user = &cfg.users[user_idx];
        let status_ip = s
            .user_statuses
            .get(user_idx)
            .map(|us| us.current_ip.clone())
            .unwrap_or_default();
        (
            cfg.server.clone(),
            user.username.clone(),
            user.clone(),
            status_ip,
            cfg.detect_ip,
            cfg.strict_bind,
            cfg.acid,
        )
    };

    let ip = user_ip::resolve_logout_ip(&user, &status_ip);

    {
        let mut s = state.lock().unwrap();
        if user_idx >= s.config.users.len() {
            return;
        }
        let uname = s.config.users[user_idx].username.clone();
        s.user_statuses[user_idx].state = LoginState::LoggingOut;
        s.add_log(format!("[INFO] {}: Logging out...", uname));
    }
    crate::service::request_ui_repaint();

    let mut client = SrunClient::new_for_logout(&server, &username, &ip, acid)
        .set_detect_ip(detect_ip)
        .set_strict_bind(strict_bind);

    match client.logout().await {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if user_idx < s.config.users.len() {
                    let uname = s.config.users[user_idx].username.clone();
                    s.user_statuses[user_idx].state = LoginState::LoggedOut;
                    s.user_statuses[user_idx].current_ip.clear();
                    s.reconnect_targets.retain(|&i| i != user_idx);
                    s.suppress_auto_reconnect = true;
                    s.add_log(format!("[OK] {}: Logout success", uname));
                }
            }
            // Refresh online_info to confirm server state after logout
            let st = state.clone();
            tokio::spawn(async move {
                sync_online_state(&st).await;
            });
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            if user_idx < s.config.users.len() {
                let uname = s.config.users[user_idx].username.clone();
                let err = e.to_string();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = err.clone();
                s.reconnect_targets.retain(|&i| i != user_idx);
                s.add_log(format!("[ERROR] {}: Logout failed - {}", uname, err));
            }
        }
    }
    crate::service::request_ui_repaint();
}

#[allow(dead_code)]
pub async fn do_login_all(state: SharedState) {
    let count = {
        let s = state.lock().unwrap();
        s.config.users.len()
    };
    for idx in 0..count {
        do_login(state.clone(), idx).await;
    }
}

#[allow(dead_code)]
pub async fn do_logout_all(state: SharedState) {
    let count = {
        let s = state.lock().unwrap();
        s.config.users.len()
    };
    for idx in 0..count {
        do_logout(state.clone(), idx).await;
    }
}

/// Try users in order, stop at the first successful login.
/// Only one user should be online at a time.
pub async fn do_one_click_login(state: SharedState) {
    let user_count = {
        let s = state.lock().unwrap();
        s.config.users.len()
    };

    if user_count == 0 {
        let mut s = state.lock().unwrap();
        s.add_log("[INFO] One-click login: no users configured".to_string());
        tracing::info!("[OneClickLogin] No users configured");
        return;
    }

    {
        let mut s = state.lock().unwrap();
        s.suppress_auto_reconnect = false;
        s.add_log("[INFO] One-click login: starting...".to_string());
    }
    crate::service::request_ui_repaint();
    tracing::info!("[OneClickLogin] Starting with {} user(s)", user_count);

    for idx in 0..user_count {
        let username = {
            let s = state.lock().unwrap();
            s.config
                .users
                .get(idx)
                .map(|u| u.username.clone())
                .unwrap_or_default()
        };

        tracing::info!("[OneClickLogin] Trying user {}: {}", idx, username);
        {
            let mut s = state.lock().unwrap();
            s.add_log(format!("[INFO] One-click login: trying {}...", username));
        }
        crate::service::request_ui_repaint();

        do_login(state.clone(), idx).await;

        let post_state = {
            let s = state.lock().unwrap();
            s.user_statuses
                .get(idx)
                .map(|us| us.state.clone())
                .unwrap_or(LoginState::Error)
        };

        match &post_state {
            LoginState::Online => {
                tracing::info!(
                    "[OneClickLogin] {} confirmed online by server, stopping",
                    username
                );
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                        "[OK] One-click login: {} confirmed online by server",
                        username
                    ));
                }
                crate::service::request_ui_repaint();
                return;
            }
            LoginState::PendingConfirm => {
                tracing::info!(
                    "[OneClickLogin] {} portal login succeeded, waiting for server confirmation, stopping",
                    username
                );
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                        "[OK] One-click login: {} login request succeeded, waiting for server confirmation",
                        username
                    ));
                }
                crate::service::request_ui_repaint();
                return;
            }
            _ => {
                let error = {
                    let s = state.lock().unwrap();
                    s.user_statuses
                        .get(idx)
                        .map(|us| us.last_error.clone())
                        .unwrap_or_default()
                };
                tracing::info!("[OneClickLogin] {} failed: {}", username, error);
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                        "[ERROR] One-click login: {} failed — {}",
                        username, error
                    ));
                }
                crate::service::request_ui_repaint();
            }
        }
    }

    tracing::info!("[OneClickLogin] All users failed");
    {
        let mut s = state.lock().unwrap();
        s.add_log("[ERROR] One-click login: all configured users failed".to_string());
    }
    crate::service::request_ui_repaint();
}

/// Log out the currently online user(s). Typically only one user is online
/// at a time; if multiple show as Online (stale state), log out all of them.
pub async fn do_one_click_logout(state: SharedState) {
    // ── Step 1: find Online users BEFORE changing any state ──
    // This must run first; otherwise LoggingOut users won't match.
    let online_indices: Vec<usize> = {
        let s = state.lock().unwrap();
        s.user_statuses
            .iter()
            .enumerate()
            .filter(|(_, us)| {
                us.state == LoginState::Online || us.state == LoginState::PendingConfirm
            })
            .map(|(i, _)| i)
            .collect()
    };

    if online_indices.is_empty() {
        let mut s = state.lock().unwrap();
        s.add_log("[WARN] One-click logout: no online user to logout".to_string());
        tracing::info!("[OneClickLogout] No online user found");
        return;
    }

    // ── Step 2: collect usernames, then set to LoggingOut ──
    {
        let mut s = state.lock().unwrap();
        let names: Vec<String> = online_indices
            .iter()
            .map(|&idx| {
                s.config
                    .users
                    .get(idx)
                    .map(|u| u.username.clone())
                    .unwrap_or_default()
            })
            .collect();
        for (i, &idx) in online_indices.iter().enumerate() {
            if let Some(us) = s.user_statuses.get_mut(idx) {
                us.state = LoginState::LoggingOut;
                us.last_error.clear();
                tracing::info!("[OneClickLogout] {} state -> LoggingOut", names[i]);
                s.add_log(format!("[INFO] {}: Logging out...", names[i]));
            }
        }
    }
    crate::service::request_ui_repaint();

    tracing::info!(
        "[OneClickLogout] Logging out {} online user(s)",
        online_indices.len()
    );

    // ── Step 3: actually log out each user ──
    for &idx in &online_indices {
        let (username, ip) = {
            let s = state.lock().unwrap();
            let uname = s
                .config
                .users
                .get(idx)
                .map(|u| u.username.clone())
                .unwrap_or_default();
            let ip = s
                .user_statuses
                .get(idx)
                .map(|us| us.current_ip.clone())
                .unwrap_or_default();
            (uname, ip)
        };

        tracing::info!(
            "[OneClickLogout] Sending logout: user={} ip={}",
            username,
            ip
        );
        {
            let mut s = state.lock().unwrap();
            s.add_log(format!(
                "[INFO] One-click logout: sending logout for {} (ip={})...",
                username, ip
            ));
        }
        crate::service::request_ui_repaint();

        do_logout(state.clone(), idx).await;
    }

    tracing::info!("[OneClickLogout] Completed");
    {
        let mut s = state.lock().unwrap();
        s.suppress_auto_reconnect = true;
        s.add_log("[OK] One-click logout: completed".to_string());
    }
    crate::service::request_ui_repaint();
}
