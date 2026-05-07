use std::time::Duration;

use crate::core::srun::SrunClient;
use crate::core::utils::get_ip_by_if_name;
use crate::platform::secure_store;
use crate::service::detection::detect_campus_ip;
use crate::service::online_info::sync_online_state;
use crate::service::{LoginState, SharedState};

pub async fn do_login(state: SharedState, user_idx: usize) {
    let (server, username, ip, detect_ip, strict_bind, double_stack, test_before_login) = {
        let s = state.lock().unwrap();
        let cfg = &s.config;
        if user_idx >= cfg.users.len() {
            return;
        }
        let user = &cfg.users[user_idx];
        // IP resolution priority:
        // 1. if_name real-time resolution (most stable across DHCP changes)
        // 2. Auto-detect current 10.x.x.x campus IPv4
        // 3. Legacy user.ip (backward compat, not recommended)
        // 4. Empty — SrunClient will try detect_ip if configured
        let ip = user
            .if_name
            .as_ref()
            .and_then(|n| get_ip_by_if_name(n))
            .filter(|i| !i.is_empty())
            .or_else(detect_campus_ip)
            .or_else(|| user.ip.clone().filter(|i| !i.is_empty()))
            .unwrap_or_default();
        (
            cfg.server.clone(),
            user.username.clone(),
            ip,
            cfg.detect_ip,
            cfg.strict_bind,
            cfg.double_stack,
            false,
        )
    };

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
        s.add_log(format!("[INFO] {}: Logging in...", uname));
    }

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
                    s.user_statuses[user_idx].state = LoginState::Online;
                    s.user_statuses[user_idx].current_ip = ip.clone();
                    s.add_log(format!("[OK] {}: Login success, IP={}", uname, ip));
                }
            }
            // Refresh online_info to populate online duration, traffic etc.
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
}

pub async fn do_logout(state: SharedState, user_idx: usize) {
    let (server, username, ip, detect_ip, strict_bind, acid) = {
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
        // IP resolution priority for logout:
        // 1. current_ip from online session (most accurate)
        // 2. if_name real-time resolution
        // 3. Auto-detect current 10.x.x.x campus IPv4
        // 4. Legacy user.ip (backward compat, not recommended)
        let ip = if !status_ip.is_empty() {
            status_ip
        } else {
            user.if_name
                .as_ref()
                .and_then(|n| get_ip_by_if_name(n))
                .filter(|i| !i.is_empty())
                .or_else(detect_campus_ip)
                .or_else(|| user.ip.clone().filter(|i| !i.is_empty()))
                .unwrap_or_default()
        };
        (
            cfg.server.clone(),
            user.username.clone(),
            ip,
            cfg.detect_ip,
            cfg.strict_bind,
            cfg.acid,
        )
    };

    {
        let mut s = state.lock().unwrap();
        if user_idx >= s.config.users.len() {
            return;
        }
        let uname = s.config.users[user_idx].username.clone();
        s.user_statuses[user_idx].state = LoginState::LoggingOut;
        s.add_log(format!("[INFO] {}: Logging out...", uname));
    }

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

        let success = {
            let s = state.lock().unwrap();
            if let Some(us) = s.user_statuses.get(idx) {
                us.state == LoginState::Online
            } else {
                false
            }
        };

        if success {
            tracing::info!("[OneClickLogin] {} succeeded, stopping", username);
            {
                let mut s = state.lock().unwrap();
                s.add_log(format!("[OK] One-click login: {} succeeded", username));
            }
            crate::service::request_ui_repaint();
            return;
        } else {
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
            .filter(|(_, us)| us.state == LoginState::Online)
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
        s.add_log("[OK] One-click logout: completed".to_string());
    }
    crate::service::request_ui_repaint();
}
