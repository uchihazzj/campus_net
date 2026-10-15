use std::time::Duration;

use crate::core::srun::SrunClient;
use crate::platform::secure_store;
use crate::service::config::StoredUser;
use crate::service::online_info::sync_online_state;
use crate::service::user_ip;
use crate::service::{LoginState, SharedState};

mod recovery;

#[derive(Clone, Copy)]
enum AuthMode {
    Login,
    Logout,
    Auto,
}

struct AuthOperation {
    state: SharedState,
    previous_states: Vec<LoginState>,
}

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
                && !crate::service::monitor::reconnect_needed(&s, true))
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
        let previous_states = s
            .user_statuses
            .iter()
            .map(|status| status.state.clone())
            .collect();
        Some(Self {
            state: state.clone(),
            previous_states,
        })
    }
}

impl Drop for AuthOperation {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.auth_busy = false;
        s.invalidate_auth_context();
        let mut interrupted = false;
        for (idx, status) in s.user_statuses.iter_mut().enumerate() {
            if matches!(status.state, LoginState::LoggingIn | LoginState::LoggingOut) {
                interrupted = true;
                if status.state == LoginState::LoggingOut {
                    apply_logout_failure(
                        status,
                        self.previous_states
                            .get(idx)
                            .cloned()
                            .unwrap_or(LoginState::Error),
                        "Authentication operation interrupted; please retry",
                    );
                } else {
                    status.state = LoginState::Error;
                    status.last_error =
                        "Authentication operation interrupted; please retry".to_string();
                }
            }
        }
        if interrupted {
            s.online_info_stale = true;
        }
        drop(s);
        crate::service::request_ui_repaint();
    }
}

pub fn spawn_login(state: SharedState, user_idx: usize) {
    if let Some(operation) = AuthOperation::begin(&state, AuthMode::Login, None) {
        tokio::spawn(async move {
            do_login_inner(state, user_idx, true).await;
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
        do_login_inner(state, user_idx, false).await;
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

fn login_context_matches(
    s: &crate::service::AppState,
    generation: u64,
    server: &str,
    idx: usize,
    expected: &StoredUser,
) -> bool {
    s.auth_busy
        && s.auth_generation == generation
        && s.config.server == server
        && s.config.users.get(idx) == Some(expected)
}

fn apply_logout_failure(
    status: &mut crate::service::UserStatus,
    previous: LoginState,
    error: &str,
) {
    status.state = if matches!(previous, LoginState::Online | LoginState::PendingConfirm) {
        previous
    } else {
        LoginState::Error
    };
    status.last_error = error.to_string();
}

fn login_blocking_account(s: &crate::service::AppState) -> Option<usize> {
    // Keep the protection while state is uncertain, but do not let a last-seen
    // account block fallback after the server/probe has established offline.
    if s.definitely_offline() {
        return None;
    }
    crate::service::online_info::confirmed_online_user_idx(s.online_info.as_ref(), &s.config.users)
}

pub(crate) fn login_will_switch_account(s: &crate::service::AppState, user_idx: usize) -> bool {
    user_idx < s.config.users.len()
        && login_blocking_account(s).is_some_and(|online_idx| online_idx != user_idx)
}

async fn logout_for_login_cleanup(
    server: String,
    account: StoredUser,
    status_ip: String,
    acid: i32,
    detect_ip: bool,
    strict_bind: bool,
) -> anyhow::Result<()> {
    let ip = user_ip::resolve_logout_ip(&account, &status_ip);
    SrunClient::new_for_logout(&server, &account.username, &ip, acid)
        .set_detect_ip(detect_ip)
        .set_strict_bind(strict_bind)
        .logout()
        .await
}

fn mark_pending_login(s: &mut crate::service::AppState, idx: usize, ip: String) {
    s.user_statuses[idx].state = LoginState::PendingConfirm;
    s.user_statuses[idx].current_ip = ip;
    s.user_statuses[idx].last_error.clear();
    s.online_info = None;
    s.online_info_fail_count = 0;
    s.online_info_stale = true;
    s.campus_auth = crate::service::CampusAuthStatus::Unknown;
}

async fn do_login_inner(state: SharedState, user_idx: usize, allow_account_switch: bool) {
    let (server, username, user, detect_ip, strict_bind, double_stack, acid, generation) = {
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
            cfg.acid,
            s.auth_generation,
        )
    };

    // Only a direct account-button click may replace an existing session.
    let switching = {
        let mut s = state.lock().unwrap();
        if !login_context_matches(&s, generation, &server, user_idx, &user) {
            return;
        }
        if let Some(online_idx) = login_blocking_account(&s) {
            if online_idx != user_idx && !allow_account_switch {
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
                drop(s);
                crate::service::request_ui_repaint();
                return;
            }
        }
        allow_account_switch && login_will_switch_account(&s, user_idx)
    };

    let password = match secure_store::decrypt_password(&user.encrypted_password) {
        Ok(p) => p,
        Err(e) => {
            let mut s = state.lock().unwrap();
            if login_context_matches(&s, generation, &server, user_idx, &user) {
                let uname = s.config.users[user_idx].username.clone();
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = format!("Password decrypt failed: {}", e);
                s.add_log(format!("[ERROR] {}: Failed to decrypt password", uname));
            }
            drop(s);
            crate::service::request_ui_repaint();
            return;
        }
    };

    if switching {
        // Validate local credentials before disturbing a working session.
        if username.trim().is_empty() || password.is_empty() {
            let mut s = state.lock().unwrap();
            if login_context_matches(&s, generation, &server, user_idx, &user) {
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error =
                    "Account switch cancelled: target username or password is empty".into();
            }
            drop(s);
            crate::service::request_ui_repaint();
            return;
        }
        let result = recovery::logout_all_before_login(
            &state,
            user_idx,
            &user,
            &server,
            "",
            recovery::CleanupReason::AccountSwitch,
            |account, status_ip| {
                logout_for_login_cleanup(
                    server.clone(),
                    account,
                    status_ip,
                    acid,
                    detect_ip,
                    strict_bind,
                )
            },
        )
        .await;
        if let Err(error) = result {
            let mut s = state.lock().unwrap();
            if login_context_matches(&s, generation, &server, user_idx, &user) {
                s.user_statuses[user_idx].state = LoginState::Error;
                s.user_statuses[user_idx].last_error = error.to_string();
                s.add_log(format!("[ERROR] {}: {}", username, error));
            }
            drop(s);
            crate::service::request_ui_repaint();
            return;
        }
    }

    // Cleanup can take time; resolve the target's current binding afterwards.
    let ip = user_ip::resolve_login_ip(&user);

    {
        let mut s = state.lock().unwrap();
        if !login_context_matches(&s, generation, &server, user_idx, &user) {
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
        .set_double_stack(double_stack);

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
                if login_context_matches(&s, generation, &server, user_idx, &user) {
                    let ip = client.client_ip.clone();
                    // Portal login succeeded but server (rad_user_info) has not
                    // yet confirmed. Do NOT mark as Online here.
                    mark_pending_login(&mut s, user_idx, ip.clone());
                    s.add_log(format!(
                        "[OK] {}: Login request succeeded (portal), IP={}, waiting for server confirmation",
                        username, ip
                    ));
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
            {
                let mut s = state.lock().unwrap();
                if !login_context_matches(&s, generation, &server, user_idx, &user) {
                    s.add_log(format!(
                        "[WARN] {}: Login error ignored because the user entry changed",
                        username
                    ));
                    return;
                }
                s.add_log(format!(
                    "[WARN] {}: Login failed - {}; starting all-account recovery",
                    username, err
                ));
            }
            crate::service::request_ui_repaint();

            let acid = client.acid;
            let result = recovery::recover_login_after_failure(
                &state,
                user_idx,
                &user,
                &server,
                &client.client_ip,
                |account, status_ip| {
                    logout_for_login_cleanup(
                        server.clone(),
                        account,
                        status_ip,
                        acid,
                        detect_ip,
                        strict_bind,
                    )
                },
                || async {
                    let retry_ip = user_ip::resolve_login_ip(&user);
                    let mut retry_client =
                        SrunClient::new(&server, &username, &password, &retry_ip)
                            .set_detect_ip(detect_ip)
                            .set_strict_bind(strict_bind)
                            .set_double_stack(double_stack);
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
                    retry_client.login().await?;
                    Ok(retry_client.client_ip)
                },
            )
            .await;
            match result {
                Ok(ip) => {
                    let applied = {
                        let mut s = state.lock().unwrap();
                        if login_context_matches(&s, generation, &server, user_idx, &user) {
                            mark_pending_login(&mut s, user_idx, ip.clone());
                            s.add_log(format!("[OK] {}: Login recovery succeeded, IP={}, waiting for server confirmation", username, ip));
                            true
                        } else {
                            false
                        }
                    };
                    if applied {
                        let st = state.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            sync_online_state(&st).await;
                        });
                    }
                }
                Err(retry_error) => {
                    let mut s = state.lock().unwrap();
                    if login_context_matches(&s, generation, &server, user_idx, &user) {
                        let detail =
                            format!("Login failed: {}; recovery failed: {}", err, retry_error);
                        s.user_statuses[user_idx].state = LoginState::Error;
                        s.user_statuses[user_idx].last_error = detail.clone();
                        s.add_log(format!("[ERROR] {}: {}", username, detail));
                    }
                }
            }
        }
    }
    crate::service::request_ui_repaint();
}

async fn do_logout_inner(state: SharedState, user_idx: usize) {
    let (server, username, user, status_ip, previous_state, detect_ip, strict_bind, acid) = {
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
            s.user_statuses[user_idx].state.clone(),
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
        s.user_statuses[user_idx].last_error.clear();
        s.online_info_stale = true;
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
                    s.user_statuses[user_idx].last_error.clear();
                    if crate::service::online_info::confirmed_online_user_idx(
                        s.online_info.as_ref(),
                        &s.config.users,
                    ) == Some(user_idx)
                    {
                        s.online_info = None;
                        s.campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
                    }
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
                apply_logout_failure(&mut s.user_statuses[user_idx], previous_state, &err);
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

/// Try users in order, stop at the first successful login.
/// Only one user should be online at a time.
pub async fn do_one_click_login(state: SharedState) {
    let Some(operation) = AuthOperation::begin(&state, AuthMode::Login, None) else {
        return;
    };
    do_one_click_login_inner(state).await;
    drop(operation);
}

pub async fn do_startup_login(state: SharedState, expected: StoredUser, expected_generation: u64) {
    let Some(operation) = AuthOperation::begin(
        &state,
        AuthMode::Auto,
        Some((0, &expected, expected_generation)),
    ) else {
        return;
    };
    do_one_click_login_inner(state).await;
    drop(operation);
}

async fn do_one_click_login_inner(state: SharedState) {
    let user_count = {
        let mut s = state.lock().unwrap();
        if s.current_online_info().is_some() {
            s.add_log(
                "[INFO] One-click login: an account is already online; keeping the current session"
                    .into(),
            );
            drop(s);
            crate::service::request_ui_repaint();
            return;
        }
        if !s.definitely_offline()
            && s.user_statuses
                .iter()
                .any(|status| status.state == LoginState::PendingConfirm)
        {
            s.add_log(
                "[INFO] One-click login: waiting for server confirmation; not repeating the login"
                    .into(),
            );
            drop(s);
            crate::service::request_ui_repaint();
            return;
        }
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

        do_login_inner(state.clone(), idx, false).await;

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

    // auth_busy disables all controls. Each account enters LoggingOut only
    // when its request starts, retaining its previous state for failed retries.
    crate::service::request_ui_repaint();

    tracing::info!(
        "[OneClickLogout] Logging out {} online user(s)",
        online_indices.len()
    );

    // ── Step 2: actually log out each user ──
    let mut failed = 0;
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
        if state
            .lock()
            .unwrap()
            .user_statuses
            .get(idx)
            .is_some_and(|status| status.state != LoginState::LoggedOut)
        {
            failed += 1;
        }
    }

    tracing::info!("[OneClickLogout] Completed");
    {
        let mut s = state.lock().unwrap();
        s.suppress_auto_reconnect = true;
        if failed == 0 {
            s.add_log("[OK] One-click logout: completed".to_string());
        } else {
            s.add_log(format!(
                "[WARN] One-click logout: {} request(s) failed; please retry",
                failed
            ));
        }
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

    fn switch_state() -> SharedState {
        let state = state();
        {
            let mut s = state.lock().unwrap();
            for index in 0..2 {
                s.config.users.push(StoredUser {
                    username: format!("test-switch-{index}"),
                    encrypted_password: "***".into(),
                    ip: Some(format!("10.0.0.{}", index + 1)),
                    if_name: None,
                });
            }
            s.ensure_statuses();
            s.user_statuses[0].state = LoginState::Online;
            s.campus_auth = crate::service::CampusAuthStatus::LoggedIn;
            s.online_info = Some(crate::service::OnlineUserInfo {
                user_name: "test-switch-0".into(),
                online_ip: "10.0.0.1".into(),
                ..Default::default()
            });
        }
        state
    }

    #[tokio::test]
    async fn invalid_switch_target_keeps_the_online_account_and_reports_its_password_error() {
        let state = switch_state();
        let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        do_login_inner(state.clone(), 1, true).await;
        drop(operation);
        let s = state.lock().unwrap();
        assert!(s.user_statuses[1]
            .last_error
            .contains("Password decrypt failed"));
        assert_eq!(s.user_statuses[0].state, LoginState::Online);
        assert!(s.current_online_info().is_some());
        assert!(s.reconnect_targets.is_empty());
        assert!(!s.authentication_busy());
    }

    #[tokio::test]
    async fn empty_switch_credentials_do_not_log_out_the_working_session() {
        for empty_password in [false, true] {
            let state = switch_state();
            {
                let mut s = state.lock().unwrap();
                let target = &mut s.config.users[1];
                if empty_password {
                    target.encrypted_password.clear();
                } else {
                    target.username.clear();
                    target.encrypted_password =
                        secure_store::encrypt_password("synthetic-switch-password").unwrap();
                }
            }
            let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
            do_login_inner(state.clone(), 1, true).await;
            drop(operation);
            let s = state.lock().unwrap();
            assert!(s.user_statuses[1].last_error.contains("is empty"));
            assert_eq!(s.user_statuses[0].state, LoginState::Online);
            assert!(s.current_online_info().is_some());
            assert!(s.reconnect_targets.is_empty());
        }
    }

    #[tokio::test]
    async fn unattended_login_keeps_the_existing_account_protection() {
        let state = switch_state();
        let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        do_login_inner(state.clone(), 1, false).await;
        drop(operation);
        let s = state.lock().unwrap();
        assert!(s.user_statuses[1]
            .last_error
            .contains("Another account is already online"));
        assert_eq!(s.user_statuses[0].state, LoginState::Online);
        assert!(s.current_online_info().is_some());
        assert!(s.reconnect_targets.is_empty());
    }

    #[test]
    fn switching_requires_a_different_account_and_no_confirmed_offline_state() {
        let state = switch_state();
        let mut s = state.lock().unwrap();
        assert!(!login_will_switch_account(&s, 0));
        assert!(login_will_switch_account(&s, 1));
        assert!(!login_will_switch_account(&s, 2));
        s.campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
        assert!(!login_will_switch_account(&s, 1));
    }

    #[tokio::test]
    async fn one_click_login_preserves_an_existing_online_session() {
        let state = state();
        {
            let mut s = state.lock().unwrap();
            for name in ["test-first", "test-online"] {
                s.config.users.push(StoredUser {
                    username: name.into(),
                    // Invalid synthetic data guarantees this test cannot send a login.
                    encrypted_password: "***".into(),
                    ip: None,
                    if_name: None,
                });
            }
            s.ensure_statuses();
            s.user_statuses[1].state = LoginState::Online;
            s.user_statuses[1].current_ip = "10.0.0.2".into();
            s.campus_auth = crate::service::CampusAuthStatus::LoggedIn;
            s.online_info = Some(crate::service::OnlineUserInfo {
                error: "ok".into(),
                user_name: "test-online".into(),
                online_ip: "10.0.0.2".into(),
                ..Default::default()
            });
        }
        do_one_click_login(state.clone()).await;
        let s = state.lock().unwrap();
        assert_eq!(s.user_statuses[0].state, LoginState::LoggedOut);
        assert_eq!(s.user_statuses[1].state, LoginState::Online);
        assert!(s.user_statuses[1].last_error.is_empty());
        assert!(!s.authentication_busy());
    }

    #[tokio::test]
    async fn one_click_login_does_not_repeat_a_pending_login() {
        let state = state();
        {
            let mut s = state.lock().unwrap();
            s.config.users.push(StoredUser {
                username: "test-pending".into(),
                encrypted_password: "***".into(),
                ip: None,
                if_name: None,
            });
            s.ensure_statuses();
            mark_pending_login(&mut s, 0, "10.0.0.2".into());
        }
        do_one_click_login(state.clone()).await;
        let s = state.lock().unwrap();
        assert_eq!(s.user_statuses[0].state, LoginState::PendingConfirm);
        assert!(s.user_statuses[0].last_error.is_empty());
        assert!(!s.authentication_busy());
    }

    #[test]
    fn failed_logout_preserves_the_session_for_retry() {
        for previous in [LoginState::Online, LoginState::PendingConfirm] {
            let mut status = crate::service::UserStatus::new();
            status.state = LoginState::LoggingOut;
            status.current_ip = "10.0.0.1".into();
            apply_logout_failure(&mut status, previous.clone(), "test timeout");
            assert_eq!(status.state, previous);
            assert_eq!(status.current_ip, "10.0.0.1");
            assert_eq!(status.last_error, "test timeout");
        }
    }

    #[test]
    fn automatic_claim_rechecks_current_auth_status() {
        let state = state();
        state.lock().unwrap().config.auto_reconnect = true;
        state.lock().unwrap().campus_auth = crate::service::CampusAuthStatus::LoggedIn;
        assert!(AuthOperation::begin(&state, AuthMode::Auto, None).is_none());
        state.lock().unwrap().campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
        state.lock().unwrap().online_query_busy = true;
        assert!(AuthOperation::begin(&state, AuthMode::Auto, None).is_none());
        state.lock().unwrap().online_query_busy = false;
        assert!(AuthOperation::begin(&state, AuthMode::Auto, None).is_some());
    }

    #[test]
    fn portal_success_does_not_repeat_login_before_confirmation() {
        let mut s = AppState::new(AppConfig::default());
        s.config.auto_reconnect = true;
        s.config.users.push(StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.ensure_statuses();
        s.campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
        mark_pending_login(&mut s, 0, "10.0.0.1".into());
        assert!(!crate::service::monitor::reconnect_needed(&s, true));
        assert_eq!(s.user_statuses[0].state, LoginState::PendingConfirm);
    }

    #[test]
    fn old_online_cache_cannot_block_confirmed_offline_reconnect() {
        let mut s = AppState::new(AppConfig::default());
        s.config.users.push(StoredUser {
            username: "test-user".into(),
            encrypted_password: String::new(),
            ip: None,
            if_name: None,
        });
        s.online_info = Some(crate::service::OnlineUserInfo {
            user_name: "test-user".into(),
            ..Default::default()
        });
        s.campus_auth = crate::service::CampusAuthStatus::LoggedIn;
        assert_eq!(login_blocking_account(&s), Some(0));
        s.online_info_stale = true;
        s.campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
        assert_eq!(login_blocking_account(&s), None);
        s.config.enable_ipv4_internet_probe = true;
        s.online_info_fail_count = 3;
        s.ipv4_internet = crate::service::Ipv4InternetStatus::CaptivePortal;
        for status in [
            crate::service::CampusAuthStatus::Unknown,
            crate::service::CampusAuthStatus::LoggedIn,
        ] {
            s.campus_auth = status;
            assert_eq!(login_blocking_account(&s), None);
        }
        s.config.enable_ipv4_internet_probe = false;
        assert_eq!(login_blocking_account(&s), Some(0));
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
    fn interrupted_logout_retains_retry_and_suppression() {
        let state = state();
        {
            let mut s = state.lock().unwrap();
            s.config.users.push(StoredUser {
                username: "test-user".into(),
                encrypted_password: String::new(),
                ip: None,
                if_name: None,
            });
            s.ensure_statuses();
            s.user_statuses[0].state = LoginState::Online;
            s.user_statuses[0].current_ip = "10.0.0.1".into();
        }
        let operation = AuthOperation::begin(&state, AuthMode::Logout, None).unwrap();
        state.lock().unwrap().user_statuses[0].state = LoginState::LoggingOut;
        drop(operation);
        let s = state.lock().unwrap();
        assert_eq!(s.user_statuses[0].state, LoginState::Online);
        assert!(!s.authentication_busy());
        assert!(s.suppress_auto_reconnect);
        assert!(s.online_info_stale);
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
        state.lock().unwrap().campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
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
        state.lock().unwrap().campus_auth = crate::service::CampusAuthStatus::NotLoggedIn;
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
