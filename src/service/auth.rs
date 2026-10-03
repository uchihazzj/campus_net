use std::time::Duration;

use crate::core::srun::SrunClient;
use crate::platform::secure_store;
use crate::service::config::StoredUser;
use crate::service::online_info::sync_online_state;
use crate::service::user_ip;
use crate::service::{LoginState, SharedState};

#[derive(Clone, Copy)]
enum AuthMode {
    Login,
    Logout,
    Auto,
}

struct AuthOperation(SharedState);

impl AuthOperation {
    fn begin(
        state: &SharedState,
        mode: AuthMode,
        expected: Option<(usize, &StoredUser, u64)>,
    ) -> Option<Self> {
        let mut s = state.lock().unwrap();
        s.ensure_statuses();
        if s.authentication_busy()
            || expected.is_some_and(|(idx, user, generation)| {
                s.config.users.get(idx) != Some(user) || s.auth_generation != generation
            })
            || (matches!(mode, AuthMode::Auto)
                && (!s.config.auto_reconnect || s.suppress_auto_reconnect))
        {
            return None;
        }
        s.auth_busy = true;
        s.invalidate_auth_context();
        match mode {
            AuthMode::Login => s.suppress_auto_reconnect = false,
            AuthMode::Logout => s.suppress_auto_reconnect = true,
            AuthMode::Auto => {}
        }
        Some(Self(state.clone()))
    }
}

impl Drop for AuthOperation {
    fn drop(&mut self) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.auth_busy = false;
        s.invalidate_auth_context();
        for status in &mut s.user_statuses {
            if matches!(status.state, LoginState::LoggingIn | LoginState::LoggingOut) {
                status.state = LoginState::Error;
                status.last_error =
                    "Authentication operation interrupted; please retry".to_string();
            }
        }
        crate::service::request_ui_repaint();
    }
}

pub fn spawn_login(state: SharedState, user_idx: usize) {
    if let Some(operation) = AuthOperation::begin(&state, AuthMode::Login, None) {
        tokio::spawn(async move {
            do_login_inner(state, user_idx).await;
            drop(operation);
        });
    }
}

pub fn spawn_logout(state: SharedState, user_idx: usize) {
    if let Some(operation) = AuthOperation::begin(&state, AuthMode::Logout, None) {
        tokio::spawn(async move {
            do_logout_inner(state, user_idx).await;
            drop(operation);
        });
    }
}

pub async fn do_auto_login(
    state: SharedState,
    user_idx: usize,
    expected: &StoredUser,
    expected_generation: u64,
) -> bool {
    if let Some(operation) = AuthOperation::begin(
        &state,
        AuthMode::Auto,
        Some((user_idx, expected, expected_generation)),
    ) {
        do_login_inner(state, user_idx).await;
        drop(operation);
        true
    } else {
        false
    }
}

fn same_user(user: &StoredUser, username: &str, original: &StoredUser) -> bool {
    user.username == username
        && user.ip == original.ip
        && user.if_name == original.if_name
        && user.encrypted_password == original.encrypted_password
}

fn user_still_matches(
    users: &[StoredUser],
    user_idx: usize,
    username: &str,
    original: &StoredUser,
) -> bool {
    users
        .get(user_idx)
        .is_some_and(|user| same_user(user, username, original))
}

fn requires_logout_retry(error: &str) -> bool {
    error
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '=')
        .any(|part| part == "err_code=2")
}

pub async fn do_login(state: SharedState, user_idx: usize) {
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Login, None) else {
        return;
    };
    do_login_inner(state, user_idx).await;
    drop(operation);
}

async fn do_login_inner(state: SharedState, user_idx: usize) {
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

    let password = match secure_store::decrypt_password(&user.encrypted_password) {
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
        if !user_still_matches(&s.config.users, user_idx, &username, &user) {
            s.add_log(format!(
                "[WARN] {}: Login cancelled because the user entry changed",
                username
            ));
            return;
        }
        s.user_statuses[user_idx].state = LoginState::LoggingIn;
        s.user_statuses[user_idx].last_error.clear();
        s.add_log(format!("[INFO] {}: Logging in...", username));
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
                if user_still_matches(&s.config.users, user_idx, &username, &user) {
                    let ip = client.client_ip.clone();
                    // Portal login succeeded but server (rad_user_info) has not
                    // yet confirmed. Do NOT mark as Online here.
                    s.user_statuses[user_idx].state = LoginState::PendingConfirm;
                    s.user_statuses[user_idx].current_ip = ip.clone();
                    s.add_log(format!(
                        "[OK] {}: Login request succeeded (portal), IP={}, waiting for server confirmation",
                        username, ip
                    ));
                    // Clear stale online_info that may belong to a different user.
                    s.online_info = None;
                    s.online_info_fail_count = 0;
                    // online_info_stale is NOT cleared here — only rad_user_info
                    // success can clear it (in sync_online_state).
                } else {
                    s.add_log(format!(
                        "[WARN] {}: Login result ignored because the user entry changed",
                        username
                    ));
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
            let err = e.to_string();

            if requires_logout_retry(&err) {
                // Auto-logout first, then retry login once
                {
                    let mut s = state.lock().unwrap();
                    s.add_log(format!(
                        "[INFO] {}: Login failed with err_code=2, auto-logging out then retrying...",
                        username
                    ));
                }
                crate::service::request_ui_repaint();

                let mut logout_client =
                    SrunClient::new_for_logout(&server, &username, &client.client_ip, client.acid)
                        .set_detect_ip(detect_ip)
                        .set_strict_bind(strict_bind);
                match logout_client.logout().await {
                    Ok(()) => {
                        {
                            let mut s = state.lock().unwrap();
                            s.add_log(format!(
                                "[OK] {}: Auto-logout done, retrying login...",
                                username
                            ));
                        }
                        crate::service::request_ui_repaint();

                        // Build fresh login client for retry
                        let mut retry_client = SrunClient::new(&server, &username, &password, &ip)
                            .set_detect_ip(detect_ip)
                            .set_strict_bind(strict_bind)
                            .set_double_stack(double_stack)
                            .set_test_before_login(test_before_login);
                        {
                            let s = state.lock().unwrap();
                            let cfg = &s.config;
                            retry_client = retry_client
                                .set_n(cfg.n)
                                .set_type(cfg.utype)
                                .set_acid(cfg.acid)
                                .set_os(&cfg.os)
                                .set_name(&cfg.name)
                                .set_retry_delay(cfg.retry_delay)
                                .set_retry_times(cfg.retry_times);
                        }

                        match retry_client.login().await {
                            Ok(()) => {
                                let mut s = state.lock().unwrap();
                                if user_still_matches(&s.config.users, user_idx, &username, &user) {
                                    let ip = retry_client.client_ip.clone();
                                    s.user_statuses[user_idx].state = LoginState::PendingConfirm;
                                    s.user_statuses[user_idx].current_ip = ip.clone();
                                    s.add_log(format!(
                                        "[OK] {}: Login retry succeeded, IP={}",
                                        username, ip
                                    ));
                                    s.online_info = None;
                                    s.online_info_fail_count = 0;
                                }
                                let st = state.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    sync_online_state(&st).await;
                                });
                            }
                            Err(e2) => {
                                let mut s = state.lock().unwrap();
                                if user_still_matches(&s.config.users, user_idx, &username, &user) {
                                    let err2 = e2.to_string();
                                    s.user_statuses[user_idx].state = LoginState::Error;
                                    s.user_statuses[user_idx].last_error = err2.clone();
                                    s.add_log(format!(
                                        "[ERROR] {}: Login retry failed - {}",
                                        username, err2
                                    ));
                                }
                            }
                        }
                    }
                    Err(logout_err) => {
                        let mut s = state.lock().unwrap();
                        if user_still_matches(&s.config.users, user_idx, &username, &user) {
                            let logout_err_str = logout_err.to_string();
                            s.user_statuses[user_idx].state = LoginState::Error;
                            s.user_statuses[user_idx].last_error =
                                format!("err_code=2, auto-logout also failed: {}", logout_err_str);
                            s.add_log(format!(
                                "[ERROR] {}: err_code=2 and auto-logout failed - {}",
                                username, logout_err_str
                            ));
                        }
                    }
                }
            } else {
                let mut s = state.lock().unwrap();
                if user_still_matches(&s.config.users, user_idx, &username, &user) {
                    s.user_statuses[user_idx].state = LoginState::Error;
                    s.user_statuses[user_idx].last_error = err.clone();
                    s.add_log(format!("[ERROR] {}: Login failed - {}", username, err));
                } else {
                    s.add_log(format!(
                        "[WARN] {}: Login error ignored because the user entry changed",
                        username
                    ));
                }
            }
        }
    }
    crate::service::request_ui_repaint();
}

pub async fn do_logout(state: SharedState, user_idx: usize) {
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Logout, None) else {
        return;
    };
    do_logout_inner(state, user_idx).await;
    drop(operation);
}

async fn do_logout_inner(state: SharedState, user_idx: usize) {
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
        if !user_still_matches(&s.config.users, user_idx, &username, &user) {
            s.add_log(format!(
                "[WARN] {}: Logout cancelled because the user entry changed",
                username
            ));
            return;
        }
        s.user_statuses[user_idx].state = LoginState::LoggingOut;
        s.add_log(format!("[INFO] {}: Logging out...", username));
    }
    crate::service::request_ui_repaint();

    let mut client = SrunClient::new_for_logout(&server, &username, &ip, acid)
        .set_detect_ip(detect_ip)
        .set_strict_bind(strict_bind);

    match client.logout().await {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if user_still_matches(&s.config.users, user_idx, &username, &user) {
                    s.user_statuses[user_idx].state = LoginState::LoggedOut;
                    s.user_statuses[user_idx].current_ip.clear();
                    s.reconnect_targets.retain(|&i| i != user_idx);
                    s.suppress_auto_reconnect = true;
                    s.add_log(format!("[OK] {}: Logout success", username));
                } else {
                    s.add_log(format!(
                        "[WARN] {}: Logout result ignored because the user entry changed",
                        username
                    ));
                }
            }
            // Refresh online_info to confirm server state after logout
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                sync_online_state(&st).await;
            });
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            if user_still_matches(&s.config.users, user_idx, &username, &user) {
                let err = e.to_string();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = err.clone();
                s.reconnect_targets.retain(|&i| i != user_idx);
                s.add_log(format!("[ERROR] {}: Logout failed - {}", username, err));
            } else {
                s.add_log(format!(
                    "[WARN] {}: Logout error ignored because the user entry changed",
                    username
                ));
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
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Login, None) else {
        return;
    };
    do_one_click_login_inner(state).await;
    drop(operation);
}

pub async fn do_startup_login(state: SharedState) {
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Auto, None) else {
        return;
    };
    do_one_click_login_inner(state).await;
    drop(operation);
}

async fn do_one_click_login_inner(state: SharedState) {
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

        do_login_inner(state.clone(), idx).await;

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
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Logout, None) else {
        return;
    };
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

        do_logout_inner(state.clone(), idx).await;
    }

    tracing::info!("[OneClickLogout] Completed");
    {
        let mut s = state.lock().unwrap();
        s.suppress_auto_reconnect = true;
        s.add_log("[OK] One-click logout: completed".to_string());
    }
    crate::service::request_ui_repaint();
    drop(operation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{config::AppConfig, AppState};
    use std::sync::{Arc, Mutex};

    fn state() -> SharedState {
        Arc::new(Mutex::new(AppState::new(AppConfig::default())))
    }

    #[test]
    fn logout_retry_requires_the_exact_error_code() {
        assert!(requires_logout_retry(
            "Login failed: err_code=2, error=login_error"
        ));
        for error in [
            "err_code=20",
            "err_code=200",
            "other_err_code=2",
            "err_code=2abc",
            "",
        ] {
            assert!(
                !requires_logout_retry(error),
                "would trigger unnecessary logout: {error}"
            );
        }
    }

    #[test]
    fn interrupted_authentication_releases_busy_state() {
        let state = state();
        let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        {
            let mut s = state.lock().unwrap();
            s.config.users.push(StoredUser {
                username: "test-user".into(),
                encrypted_password: String::new(),
                ip: None,
                if_name: None,
            });
            s.ensure_statuses();
            s.user_statuses[0].state = LoginState::LoggingIn;
        }
        drop(operation);
        assert!(!state.lock().unwrap().authentication_busy());
        assert_eq!(
            state.lock().unwrap().user_statuses[0].state,
            LoginState::Error
        );
        assert!(AuthOperation::begin(&state, AuthMode::Login, None).is_some());
    }

    #[test]
    fn auth_operations_are_exclusive_and_invalidate_old_queries() {
        let state = state();
        let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        assert!(AuthOperation::begin(&state, AuthMode::Logout, None).is_none());
        assert_eq!(state.lock().unwrap().auth_generation, 1);
        drop(operation);
        assert!(!state.lock().unwrap().auth_busy);
        assert_eq!(state.lock().unwrap().auth_generation, 2);
    }

    #[test]
    fn manual_logout_suppresses_reconnect_before_network_work() {
        let state = state();
        let operation = AuthOperation::begin(&state, AuthMode::Logout, None).unwrap();
        assert!(state.lock().unwrap().suppress_auto_reconnect);
        drop(operation);
        assert!(AuthOperation::begin(&state, AuthMode::Auto, None).is_none());
        assert!(state.lock().unwrap().suppress_auto_reconnect);
    }

    #[test]
    fn automatic_login_rejects_shifted_account_indices() {
        let state = state();
        let user = StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        };
        state.lock().unwrap().config.users.push(user.clone());
        let other = StoredUser {
            username: "other-test-user".into(),
            ..user
        };
        assert!(AuthOperation::begin(&state, AuthMode::Auto, Some((0, &other, 0))).is_none());
        assert!(!state.lock().unwrap().auth_busy);
    }

    #[test]
    fn manual_authentication_invalidates_an_older_reconnect_batch() {
        let state = state();
        let user = StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        };
        state.lock().unwrap().config.users.push(user.clone());
        let initial_generation = state.lock().unwrap().auth_generation;
        let first_auto =
            AuthOperation::begin(&state, AuthMode::Auto, Some((0, &user, initial_generation)))
                .unwrap();
        drop(first_auto);
        let next_generation = initial_generation.wrapping_add(2);
        let manual = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        drop(manual);
        assert!(
            AuthOperation::begin(&state, AuthMode::Auto, Some((0, &user, next_generation)))
                .is_none()
        );
    }

    #[test]
    fn reconnect_batch_can_continue_after_its_own_failed_attempt() {
        let state = state();
        let user = StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        };
        state.lock().unwrap().config.users.push(user.clone());
        let generation = state.lock().unwrap().auth_generation;
        let first =
            AuthOperation::begin(&state, AuthMode::Auto, Some((0, &user, generation))).unwrap();
        drop(first);
        assert!(AuthOperation::begin(
            &state,
            AuthMode::Auto,
            Some((0, &user, generation.wrapping_add(2)))
        )
        .is_some());
    }
}
