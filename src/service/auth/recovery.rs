use std::future::Future;

use crate::service::config::StoredUser;
use crate::service::{AppState, CampusAuthStatus, LoginState, SharedState};

fn context_matches(s: &AppState, generation: u64, users: &[StoredUser], server: &str) -> bool {
    s.auth_busy
        && s.auth_generation == generation
        && s.config.server == server
        && s.config.users == users
}

/// Executes one recovery round inside the caller's authentication operation.
/// Callbacks keep the ordering/state policy testable without network requests.
pub(super) async fn recover_login_after_failure<L, LF, R, RF>(
    state: &SharedState,
    target_idx: usize,
    expected: &StoredUser,
    server: &str,
    failed_ip: &str,
    mut logout: L,
    retry: R,
) -> anyhow::Result<String>
where
    L: FnMut(StoredUser, String) -> LF,
    LF: Future<Output = anyhow::Result<()>>,
    R: FnOnce() -> RF,
    RF: Future<Output = anyhow::Result<String>>,
{
    let (users, status_ips, generation) = {
        let mut s = state.lock().unwrap();
        if !s.auth_busy
            || s.config.server != server
            || s.config.users.get(target_idx) != Some(expected)
        {
            anyhow::bail!("Login recovery cancelled: authentication context changed");
        }
        s.ensure_statuses();
        let users = s.config.users.clone();
        let mut status_ips: Vec<_> = s
            .user_statuses
            .iter()
            .map(|status| status.current_ip.clone())
            .collect();
        if !failed_ip.is_empty() {
            status_ips[target_idx] = failed_ip.to_string();
        }
        // Logout attempts invalidate the old session cache. Keep the existing
        // offline evidence and generations so an automatic batch can continue.
        s.online_info = None;
        s.online_info_stale = true;
        if s.campus_auth == CampusAuthStatus::LoggedIn {
            s.campus_auth = CampusAuthStatus::Unknown;
        }
        s.add_log(format!(
            "[INFO] Login recovery: logging out all {} configured account(s) once",
            users.len()
        ));
        (users, status_ips, s.auth_generation)
    };
    crate::service::request_ui_repaint();

    let mut failures = 0;
    for (idx, user) in users.iter().enumerate() {
        let previous = {
            let mut s = state.lock().unwrap();
            if !context_matches(&s, generation, &users, server) {
                anyhow::bail!("Login recovery cancelled: authentication context changed");
            }
            s.ensure_statuses();
            let previous = s.user_statuses[idx].state.clone();
            s.user_statuses[idx].state = LoginState::LoggingOut;
            s.user_statuses[idx].last_error.clear();
            s.add_log(format!(
                "[INFO] Login recovery: logout {}/{} — {}",
                idx + 1,
                users.len(),
                user.username
            ));
            previous
        };
        crate::service::request_ui_repaint();
        let result = logout(user.clone(), status_ips[idx].clone()).await;
        {
            let mut s = state.lock().unwrap();
            if !context_matches(&s, generation, &users, server) {
                anyhow::bail!("Login recovery cancelled: authentication context changed");
            }
            match result {
                Ok(()) => {
                    s.user_statuses[idx].state = LoginState::LoggedOut;
                    s.user_statuses[idx].current_ip.clear();
                    s.user_statuses[idx].last_error.clear();
                    s.add_log(format!(
                        "[OK] Login recovery: {} logout completed",
                        user.username
                    ));
                }
                Err(error) => {
                    failures += 1;
                    super::apply_logout_failure(
                        &mut s.user_statuses[idx],
                        previous,
                        &error.to_string(),
                    );
                    s.add_log(format!(
                        "[WARN] Login recovery: {} logout failed — {}; continuing",
                        user.username, error
                    ));
                }
            }
        }
        crate::service::request_ui_repaint();
    }

    {
        let mut s = state.lock().unwrap();
        if !context_matches(&s, generation, &users, server) {
            anyhow::bail!("Login recovery cancelled: authentication context changed");
        }
        // Internal recovery never enters AuthMode::Logout: that would pause
        // auto-reconnect and conflict with the caller's authentication lock.
        s.user_statuses[target_idx].state = LoginState::LoggingIn;
        s.user_statuses[target_idx].last_error.clear();
        s.add_log(format!(
            "[INFO] Login recovery: cleanup complete ({} failed), retrying {} once",
            failures, expected.username
        ));
    }
    crate::service::request_ui_repaint();
    let result = retry().await;
    if !context_matches(&state.lock().unwrap(), generation, &users, server) {
        anyhow::bail!("Login recovery cancelled: authentication context changed");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::{AuthMode, AuthOperation};
    use crate::service::{config::AppConfig, AppState, CampusAuthStatus, LoginState};
    use std::sync::{Arc, Mutex};

    fn fixture() -> (SharedState, AuthOperation, StoredUser) {
        let users: Vec<_> = (0..4)
            .map(|i| StoredUser {
                username: format!("preview-recovery-{i}"),
                encrypted_password: "***".into(),
                ip: Some(format!("10.0.0.{}", i + 1)),
                if_name: None,
            })
            .collect();
        let expected = users[2].clone();
        let mut s = AppState::new(AppConfig {
            users,
            server: "http://auth.example.test".into(),
            ..Default::default()
        });
        for (status, login) in s.user_statuses.iter_mut().zip([
            LoginState::LoggedOut,
            LoginState::Online,
            LoginState::Error,
            LoginState::PendingConfirm,
        ]) {
            status.state = login;
        }
        s.user_statuses[1].current_ip = "10.0.0.51".into();
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        let state = Arc::new(Mutex::new(s));
        let operation = AuthOperation::begin(&state, AuthMode::Login, None).unwrap();
        state.lock().unwrap().user_statuses[2].state = LoginState::LoggingIn;
        (state, operation, expected)
    }

    #[tokio::test]
    async fn every_configured_account_is_logged_out_before_the_original_target_retries() {
        let (state, _operation, expected) = fixture();
        let actions = Arc::new(Mutex::new(Vec::new()));
        let generation = state.lock().unwrap().auth_generation;
        let result = recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |user, status_ip| {
                let actions = actions.clone();
                let state = state.clone();
                async move {
                    assert!(
                        state
                            .try_lock()
                            .expect("state lock held during logout")
                            .auth_busy
                    );
                    let ip = crate::service::user_ip::resolve_logout_ip(&user, &status_ip);
                    actions
                        .lock()
                        .unwrap()
                        .push(format!("logout:{}:{ip}", user.username));
                    tokio::task::yield_now().await;
                    Ok(())
                }
            },
            || {
                let actions = actions.clone();
                let state = state.clone();
                let expected = expected.clone();
                async move {
                    assert_eq!(
                        state
                            .try_lock()
                            .expect("state lock held during retry")
                            .user_statuses[2]
                            .state,
                        LoginState::LoggingIn
                    );
                    actions
                        .lock()
                        .unwrap()
                        .push(format!("login:{}", expected.username));
                    Ok("10.0.0.99".into())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, "10.0.0.99");
        assert_eq!(
            *actions.lock().unwrap(),
            [
                "logout:preview-recovery-0:10.0.0.1",
                "logout:preview-recovery-1:10.0.0.51",
                "logout:preview-recovery-2:10.0.0.99",
                "logout:preview-recovery-3:10.0.0.4",
                "login:preview-recovery-2",
            ]
        );
        let s = state.lock().unwrap();
        assert!(!s.suppress_auto_reconnect);
        assert_eq!(
            s.auth_generation, generation,
            "recovery must not create another auth operation"
        );
        assert!(s
            .user_statuses
            .iter()
            .enumerate()
            .all(|(idx, status)| idx == 2 || status.state == LoginState::LoggedOut));
    }

    #[tokio::test]
    async fn a_failed_logout_does_not_skip_other_accounts_or_the_target_retry() {
        let (state, _operation, expected) = fixture();
        let actions = Arc::new(Mutex::new(Vec::new()));
        recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |user, _| {
                let actions = actions.clone();
                async move {
                    actions.lock().unwrap().push(user.username.clone());
                    if user.username.ends_with('1') {
                        anyhow::bail!("synthetic logout timeout");
                    }
                    Ok(())
                }
            },
            || async {
                actions.lock().unwrap().push("retry target 2".into());
                Ok("10.0.0.99".into())
            },
        )
        .await
        .unwrap();
        assert_eq!(actions.lock().unwrap().len(), 5);
        let s = state.lock().unwrap();
        assert_eq!(s.user_statuses[1].state, LoginState::Online);
        assert_eq!(s.user_statuses[1].last_error, "synthetic logout timeout");
        assert_eq!(s.user_statuses[3].state, LoginState::LoggedOut);
        assert!(!s.suppress_auto_reconnect);
    }

    #[tokio::test]
    async fn retry_failure_finishes_after_one_cleanup_round() {
        let (state, _operation, expected) = fixture();
        let actions = Arc::new(Mutex::new(Vec::new()));
        let error = recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |user, _| {
                let actions = actions.clone();
                async move {
                    actions.lock().unwrap().push(user.username);
                    Ok(())
                }
            },
            || async {
                actions.lock().unwrap().push("retry target 2".into());
                anyhow::bail!("synthetic login rejection")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "synthetic login rejection");
        assert_eq!(actions.lock().unwrap().len(), 5);
        assert!(!state.lock().unwrap().suppress_auto_reconnect);
    }

    #[tokio::test]
    async fn changed_context_cancels_remaining_logouts_and_never_retries() {
        let (state, _operation, expected) = fixture();
        let actions = Arc::new(Mutex::new(Vec::new()));
        let error = recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |user, _| {
                let actions = actions.clone();
                let state = state.clone();
                async move {
                    actions.lock().unwrap().push(user.username);
                    let mut s = state.lock().unwrap();
                    s.config.users[0].username = "preview-replacement".into();
                    s.invalidate_auth_context();
                    Ok(())
                }
            },
            || async { panic!("must not retry after context changes") },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("context changed"));
        assert_eq!(actions.lock().unwrap().len(), 1);
        assert_eq!(
            state.lock().unwrap().config.users[0].username,
            "preview-replacement"
        );
    }

    #[tokio::test]
    async fn recovery_cannot_run_without_the_original_authentication_operation() {
        let (state, operation, expected) = fixture();
        drop(operation);
        assert!(recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |_, _| async { panic!("must not log out without an auth operation") },
            || async { panic!("must not retry without an auth operation") }
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn a_late_retry_result_cannot_complete_a_changed_context() {
        let (state, _operation, expected) = fixture();
        let error = recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |_, _| async { Ok(()) },
            || async {
                state.lock().unwrap().invalidate_auth_context();
                Ok("10.0.0.99".into())
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("context changed"));
    }
}
