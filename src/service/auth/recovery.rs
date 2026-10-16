use std::future::Future;

use crate::service::config::StoredUser;
use crate::service::{AppState, CampusAuthStatus, LoginState, SharedState};

fn context_matches(s: &AppState, generation: u64, users: &[StoredUser], server: &str) -> bool {
    s.auth_busy
        && s.auth_generation == generation
        && s.config.server == server
        && s.config.users == users
}

pub(super) enum CleanupReason {
    LoginFailure,
    AccountSwitch,
}

impl CleanupReason {
    fn label(&self) -> &'static str {
        match self {
            Self::LoginFailure => "Login recovery",
            Self::AccountSwitch => "Account switch",
        }
    }
}

pub(super) struct CleanupContext {
    users: Vec<StoredUser>,
    generation: u64,
}

/// Executes one recovery round inside the caller's authentication operation.
/// Callbacks keep the ordering/state policy testable without network requests.
pub(super) async fn recover_login_after_failure<L, LF, R, RF>(
    state: &SharedState,
    target_idx: usize,
    expected: &StoredUser,
    server: &str,
    failed_ip: &str,
    logout: L,
    retry: R,
) -> anyhow::Result<String>
where
    L: FnMut(StoredUser, String) -> LF,
    LF: Future<Output = anyhow::Result<()>>,
    R: FnOnce() -> RF,
    RF: Future<Output = anyhow::Result<String>>,
{
    let context = logout_all_before_login(
        state,
        target_idx,
        expected,
        server,
        failed_ip,
        CleanupReason::LoginFailure,
        logout,
    )
    .await?;
    let result = retry().await;
    if !context_matches(
        &state.lock().unwrap(),
        context.generation,
        &context.users,
        server,
    ) {
        anyhow::bail!("Login recovery cancelled: authentication context changed");
    }
    result
}

/// Reuses the caller's authentication lock; never starts a separate logout operation.
pub(super) async fn logout_all_before_login<L, LF>(
    state: &SharedState,
    target_idx: usize,
    expected: &StoredUser,
    server: &str,
    failed_ip: &str,
    reason: CleanupReason,
    mut logout: L,
) -> anyhow::Result<CleanupContext>
where
    L: FnMut(StoredUser, String) -> LF,
    LF: Future<Output = anyhow::Result<()>>,
{
    let label = reason.label();
    let (users, status_ips, generation) = {
        let mut s = state.lock().unwrap();
        if !s.auth_busy
            || s.config.server != server
            || s.config.users.get(target_idx) != Some(expected)
        {
            anyhow::bail!("{} cancelled: authentication context changed", label);
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
        if matches!(reason, CleanupReason::AccountSwitch) {
            s.reconnect_targets = vec![target_idx];
        }
        s.add_log(format!(
            "[INFO] {}: logging out all {} configured account(s) once",
            label,
            users.len()
        ));
        (users, status_ips, s.auth_generation)
    };
    crate::service::request_ui_repaint();

    crate::service::diagnostics::auth_event(
        state,
        target_idx,
        match reason {
            CleanupReason::LoginFailure => crate::service::diagnostics::AuthEvent::RecoveryStart,
            CleanupReason::AccountSwitch => crate::service::diagnostics::AuthEvent::SwitchCleanup,
        },
        None,
    );

    let mut failures = 0;
    for (idx, user) in users.iter().enumerate() {
        let previous = {
            let mut s = state.lock().unwrap();
            if !context_matches(&s, generation, &users, server) {
                anyhow::bail!("{} cancelled: authentication context changed", label);
            }
            s.ensure_statuses();
            let previous = s.user_statuses[idx].state.clone();
            s.user_statuses[idx].state = LoginState::LoggingOut;
            s.user_statuses[idx].last_error.clear();
            s.add_log(format!(
                "[INFO] {}: logout {}/{} — {}",
                label,
                idx + 1,
                users.len(),
                user.username
            ));
            previous
        };
        crate::service::request_ui_repaint();
        let result = logout(user.clone(), status_ips[idx].clone()).await;
        crate::service::diagnostics::auth_event(
            state,
            idx,
            if result.is_ok() {
                crate::service::diagnostics::AuthEvent::RecoveryLogoutOk
            } else {
                crate::service::diagnostics::AuthEvent::RecoveryLogoutFailed
            },
            result
                .as_ref()
                .err()
                .map(|error| error.to_string())
                .as_deref(),
        );
        {
            let mut s = state.lock().unwrap();
            if !context_matches(&s, generation, &users, server) {
                anyhow::bail!("{} cancelled: authentication context changed", label);
            }
            match result {
                Ok(()) => {
                    s.user_statuses[idx].state = LoginState::LoggedOut;
                    s.user_statuses[idx].current_ip.clear();
                    s.user_statuses[idx].last_error.clear();
                    s.add_log(format!(
                        "[OK] {}: {} logout completed",
                        label, user.username
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
                        "[WARN] {}: {} logout failed — {}; continuing",
                        label, user.username, error
                    ));
                }
            }
        }
        crate::service::request_ui_repaint();
    }

    {
        let mut s = state.lock().unwrap();
        if !context_matches(&s, generation, &users, server) {
            anyhow::bail!("{} cancelled: authentication context changed", label);
        }
        // Internal recovery never enters AuthMode::Logout: that would pause
        // auto-reconnect and conflict with the caller's authentication lock.
        s.user_statuses[target_idx].state = LoginState::LoggingIn;
        s.user_statuses[target_idx].last_error.clear();
        let next = match reason {
            CleanupReason::LoginFailure => "retrying",
            CleanupReason::AccountSwitch => "logging in to",
        };
        s.add_log(format!(
            "[INFO] {}: cleanup complete ({} failed), {} {}",
            label, failures, next, expected.username
        ));
    }
    crate::service::request_ui_repaint();
    Ok(CleanupContext { users, generation })
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
    async fn switch_cleanup_uses_each_old_ip_and_prepares_only_the_selected_account() {
        for fail_one_logout in [false, true] {
            let (state, operation, expected) = fixture();
            let generation = {
                let mut s = state.lock().unwrap();
                s.user_statuses[2].current_ip = "10.0.0.77".into();
                s.campus_auth = CampusAuthStatus::LoggedIn;
                s.reconnect_targets = vec![1];
                s.auth_generation
            };
            let actions = Arc::new(Mutex::new(Vec::new()));
            logout_all_before_login(
                &state,
                2,
                &expected,
                "http://auth.example.test",
                "",
                CleanupReason::AccountSwitch,
                |user, status_ip| {
                    let state = state.clone();
                    let actions = actions.clone();
                    async move {
                        {
                            let s = state.try_lock().expect("lock held during synthetic logout");
                            assert!(s.auth_busy);
                            assert!(!s.suppress_auto_reconnect);
                            assert_eq!(s.auth_generation, generation);
                        }
                        assert!(AuthOperation::begin(&state, AuthMode::Login, None).is_none());
                        let ip = crate::service::user_ip::resolve_logout_ip(&user, &status_ip);
                        actions
                            .lock()
                            .unwrap()
                            .push(format!("{}:{ip}", user.username));
                        tokio::task::yield_now().await;
                        if fail_one_logout && user.username.ends_with('1') {
                            anyhow::bail!("synthetic switch logout timeout");
                        }
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(
                *actions.lock().unwrap(),
                [
                    "preview-recovery-0:10.0.0.1",
                    "preview-recovery-1:10.0.0.51",
                    "preview-recovery-2:10.0.0.77",
                    "preview-recovery-3:10.0.0.4",
                ]
            );
            {
                let s = state.lock().unwrap();
                assert_eq!(s.user_statuses[2].state, LoginState::LoggingIn);
                assert_eq!(s.user_statuses[3].state, LoginState::LoggedOut);
                assert_eq!(s.reconnect_targets, vec![2]);
                assert_eq!(s.campus_auth, CampusAuthStatus::Unknown);
                assert!(!s.suppress_auto_reconnect);
                assert_eq!(s.auth_generation, generation);
                if fail_one_logout {
                    assert_eq!(s.user_statuses[1].state, LoginState::Online);
                    assert_eq!(
                        s.user_statuses[1].last_error,
                        "synthetic switch logout timeout"
                    );
                }
            }
            drop(operation);
            assert!(!state.lock().unwrap().authentication_busy());
            assert_eq!(
                state.lock().unwrap().auth_generation,
                generation.wrapping_add(1)
            );
        }
    }

    #[tokio::test]
    async fn cancelling_switch_cleanup_releases_the_operation_without_starting_a_login() {
        let (state, operation, expected) = fixture();
        let generation = state.lock().unwrap().auth_generation;
        let mut cleanup = Box::pin(logout_all_before_login(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "",
            CleanupReason::AccountSwitch,
            |_, _| std::future::pending::<anyhow::Result<()>>(),
        ));
        tokio::select! {
            biased;
            _ = &mut cleanup => panic!("synthetic logout must remain pending"),
            _ = std::future::ready(()) => {}
        }
        assert_eq!(
            state.lock().unwrap().user_statuses[0].state,
            LoginState::LoggingOut
        );
        drop(cleanup);
        drop(operation);
        let s = state.lock().unwrap();
        assert!(!s.authentication_busy());
        assert!(!s.suppress_auto_reconnect);
        assert_eq!(s.auth_generation, generation.wrapping_add(1));
        assert_eq!(s.user_statuses[1].state, LoginState::Online);
        assert_eq!(s.user_statuses[2].state, LoginState::Error);
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

    #[tokio::test]
    async fn functional_trace_observes_real_cleanup_order_without_transport_or_payloads() {
        use crate::service::diagnostics::{DiagnosticMode, FunctionalPhase, RunStatus};
        let (state, _operation, expected) = fixture();
        {
            let mut s = state.lock().unwrap();
            s.diagnostics.mode = DiagnosticMode::Functional;
            s.diagnostics.status = RunStatus::Running;
            s.diagnostics.phase = FunctionalPhase::Testing;
        }
        let result = recover_login_after_failure(
            &state,
            2,
            &expected,
            "http://auth.example.test",
            "10.0.0.99",
            |_, _| async { Err(anyhow::anyhow!("err_code=2 PRIVATE-PAYLOAD")) },
            || async { Ok("10.0.0.99".into()) },
        )
        .await;
        assert!(result.is_ok());
        let s = state.lock().unwrap();
        let events: Vec<_> = s.diagnostics.report.lines().collect();
        assert!(events[0].contains("A3 recovery_all_accounts_begin"));
        for index in 0..4 {
            assert!(events[index + 1].contains(&format!(
                "A{} cleanup_account_failed category=server_rejected err_code=2",
                index + 1
            )));
        }
        assert!(!s.diagnostics.report.contains("PRIVATE-PAYLOAD"));
        assert!(!s.diagnostics.report.contains("preview-recovery"));
        assert!(!s.diagnostics.report.contains("10.0.0."));
    }
}
