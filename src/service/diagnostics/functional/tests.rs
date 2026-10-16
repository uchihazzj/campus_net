//! The functional-test orchestrator uses fake actions; never run auth transports.
use std::sync::Mutex;

use super::*;
use crate::service::diagnostics::tests::{fixture, ReportPath};

struct Mock {
    state: SharedState,
    baseline: Baseline,
    actions: Mutex<Vec<Action>>,
    confirmations: Mutex<Vec<Option<usize>>>,
    fail: Option<Action>,
    cancel: Option<Action>,
    panic: Option<Action>,
    fail_restore: bool,
    fail_preflight: bool,
    panic_restore: bool,
    session: Mutex<Option<usize>>,
    _owner: Arc<DiagnosticSession>,
}

impl ProbeBackend for Mock {
    async fn probe(&self, _: Target) -> Check {
        pass("fixture_probe")
    }
    async fn sessions(
        &self,
        _: usize,
    ) -> Result<Vec<std::net::IpAddr>, crate::service::online_sessions::QueryError> {
        Ok(Vec::new())
    }
}

impl Backend for Mock {
    async fn preflight(&self) -> Result<Baseline, Failure> {
        if self.fail_preflight {
            Err(Failure::new("restore_credentials"))
        } else {
            Ok(self.baseline)
        }
    }
    async fn action(&self, action: Action) -> Result<(), Failure> {
        self.actions.lock().unwrap().push(action);
        let restoring = self.state.lock().unwrap().diagnostics.phase == FunctionalPhase::Restoring;
        if !restoring {
            if self.cancel == Some(action) {
                if let Action::Login(index) = action {
                    *self.session.lock().unwrap() = Some(index);
                }
                self.state.lock().unwrap().diagnostics.cancel_requested = true;
                return std::future::pending().await;
            }
            assert!(self.panic != Some(action), "fixture action panic");
            if self.fail == Some(action) {
                return Err(Failure::from_text(
                    "err_code=2 fixture-account-SECRET 10.9.8.7 token-SECRET",
                ));
            }
        }
        if restoring && self.fail_restore {
            return Err(Failure::new("network_error"));
        }
        let mut session = self.session.lock().unwrap();
        match action {
            Action::Logout(index) if *session == Some(index) => *session = None,
            Action::Login(index) | Action::Reconnect(index) => {
                if session.is_some_and(|online| online != index) {
                    return Err(Failure::new("another_account_online"));
                }
                *session = Some(index);
            }
            _ => {}
        }
        Ok(())
    }
    async fn confirm(&self, expected: Option<usize>) -> Result<(), Failure> {
        self.confirmations.lock().unwrap().push(expected);
        assert!(
            !(self.panic_restore
                && self.state.lock().unwrap().diagnostics.phase == FunctionalPhase::Restoring),
            "fixture restore panic"
        );
        if *self.session.lock().unwrap() == expected {
            Ok(())
        } else {
            Err(Failure::new("unexpected_session"))
        }
    }
}

fn setup(baseline: Baseline) -> (SharedState, Ticket, Mock, ReportPath) {
    let state = fixture();
    {
        let mut s = state.lock().unwrap();
        let mut second = s.config.users[0].clone();
        second.username = "fixture-other-SECRET".into();
        s.config.users.push(second);
        s.ensure_statuses();
        s.diagnostics.mode = DiagnosticMode::Functional;
        s.diagnostics.selected_account = 1;
        s.suppress_auto_reconnect = true;
    }
    let mut ticket = super::super::claim(&state).unwrap();
    let owner = Arc::new(DiagnosticSession::begin(&state).unwrap());
    {
        let mut s = state.lock().unwrap();
        ticket.generation = s.auth_generation;
        s.diagnostics.phase = FunctionalPhase::Testing;
    }
    let backend = Mock {
        state: state.clone(),
        baseline,
        actions: Mutex::default(),
        confirmations: Mutex::default(),
        fail: None,
        cancel: None,
        panic: None,
        fail_restore: false,
        fail_preflight: false,
        panic_restore: false,
        session: Mutex::new(match baseline {
            Baseline::Online(index) => Some(index),
            Baseline::Offline => None,
        }),
        _owner: owner,
    };
    (state, ticket, backend, ReportPath::new())
}

#[tokio::test]
async fn real_action_plan_logs_out_logs_in_reconnects_and_restores_the_original_account() {
    let (state, ticket, mock, path) = setup(Baseline::Online(0));
    let config = serde_json::to_value(&state.lock().unwrap().config).unwrap();
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        *backend.actions.lock().unwrap(),
        vec![
            Action::Logout(0),
            Action::Login(1),
            Action::Logout(1),
            Action::Reconnect(1),
            Action::Logout(1),
            Action::Login(0)
        ]
    );
    assert_eq!(
        *backend.confirmations.lock().unwrap(),
        vec![None, Some(1), None, Some(1), Some(0), None, Some(0)]
    );
    assert!(state.lock().unwrap().diagnostics.status == RunStatus::Completed);
    assert!(state.lock().unwrap().auth_busy);
    drop(backend);
    let id = state.lock().unwrap().diagnostics.sequence;
    super::super::save(&state, id, &path.0).await;
    let s = state.lock().unwrap();
    assert!(!s.auth_busy);
    assert!(s.suppress_auto_reconnect);
    assert_eq!(serde_json::to_value(&s.config).unwrap(), config);
    assert!(s
        .diagnostics
        .report
        .contains("PASS restore original_state_confirmed"));
    assert!(s
        .diagnostics
        .report
        .contains("not_triggered_no_wrong_password_injected"));
    assert!(!s.diagnostics.report.contains("SECRET"));
    assert_eq!(
        std::fs::read_to_string(&path.0).unwrap(),
        s.diagnostics.report
    );
}

#[tokio::test]
async fn initially_offline_test_ends_by_logging_out_the_test_account() {
    let (state, ticket, mock, path) = setup(Baseline::Offline);
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        backend.actions.lock().unwrap().last(),
        Some(&Action::Logout(1))
    );
    assert_eq!(backend.confirmations.lock().unwrap().last(), Some(&None));
    assert!(state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("original=offline test=A2"));
}

#[tokio::test]
async fn failed_login_does_not_continue_to_reconnect_and_still_restores() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.fail = Some(Action::Login(1));
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        *backend.actions.lock().unwrap(),
        vec![
            Action::Logout(0),
            Action::Login(1),
            Action::Logout(1),
            Action::Login(0)
        ]
    );
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.status == RunStatus::Failed);
    assert!(d.report.contains("err_code=2"));
    assert!(d.report.contains("PASS restore original_state_confirmed"));
    assert!(!d.report.contains("SECRET"));
    assert!(!d.report.contains("10.9.8.7"));
}

#[tokio::test]
async fn cancellation_waits_for_restoration_before_releasing_auth_ownership() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.cancel = Some(Action::Login(1));
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        backend.actions.lock().unwrap().last(),
        Some(&Action::Login(0))
    );
    assert!(state.lock().unwrap().diagnostics.status == RunStatus::Cancelled);
    assert!(state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("PASS restore original_state_confirmed"));
    assert!(state.lock().unwrap().auth_busy);
    drop(backend);
    assert!(!state.lock().unwrap().auth_busy);
}

#[tokio::test]
async fn panic_in_the_test_worker_also_runs_restoration() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.panic = Some(Action::Login(1));
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        backend.actions.lock().unwrap().last(),
        Some(&Action::Login(0))
    );
    assert!(state.lock().unwrap().diagnostics.status == RunStatus::Interrupted);
    assert!(state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("PASS restore original_state_confirmed"));
}

#[tokio::test]
async fn restoration_failure_is_explicit_and_preserves_the_original_reconnect_target() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.fail_restore = true;
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    drop(backend);
    let s = state.lock().unwrap();
    assert!(s.diagnostics.status == RunStatus::RestoreFailed);
    assert_eq!(s.reconnect_targets, vec![0]);
    assert!(!s.auth_busy);
    assert!(s.suppress_auto_reconnect);
    assert!(s.diagnostics.report.contains("FAIL restore network_error"));
}

#[tokio::test]
async fn invalid_preflight_never_sends_a_login_or_logout() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.fail_preflight = true;
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert!(backend.actions.lock().unwrap().is_empty());
    assert!(state.lock().unwrap().diagnostics.status == RunStatus::Failed);
}

#[tokio::test]
async fn disabled_auto_reconnect_is_skipped_without_changing_config() {
    let (state, mut ticket, mock, path) = setup(Baseline::Online(0));
    state.lock().unwrap().config.auto_reconnect = false;
    ticket.config.auto_reconnect = false;
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert!(!backend
        .actions
        .lock()
        .unwrap()
        .iter()
        .any(|action| matches!(action, Action::Reconnect(_))));
    assert!(state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("SKIP reconnect disabled_by_config"));
    assert!(!state.lock().unwrap().config.auto_reconnect);
}

#[test]
fn auth_errors_are_categories_and_numeric_codes_only() {
    for error in [
        "err_code=2 account-SECRET",
        "err_code2 token-SECRET",
        "err_code: 2 10.9.8.7",
        "err_code\":\"2 password-SECRET",
    ] {
        let details = Failure::from_text(error).details();
        assert_eq!(details, " category=server_rejected err_code=2");
    }
    assert_eq!(
        Failure::from_text("server msg 乱码 SECRET").details(),
        " category=operation_failed"
    );
}

#[test]
fn auth_trace_is_manual_only_bounded_and_does_not_copy_error_payloads() {
    let state = fixture();
    auth_event(&state, 0, AuthEvent::LoginFailed, Some("err_code=2 SECRET"));
    assert!(state.lock().unwrap().diagnostics.report.is_empty());
    {
        let mut s = state.lock().unwrap();
        s.diagnostics.mode = DiagnosticMode::Functional;
        s.diagnostics.status = RunStatus::Running;
        s.diagnostics.phase = FunctionalPhase::Testing;
    }
    for _ in 0..130 {
        auth_event(&state, 0, AuthEvent::LoginFailed, Some("err_code=2 SECRET"));
    }
    let s = state.lock().unwrap();
    assert_eq!(s.diagnostics.report.lines().count(), 96);
    assert_eq!(s.diagnostics.auth_events_dropped, 34);
    assert!(!s.diagnostics.report.contains("SECRET"));
}

#[tokio::test]
async fn stalled_report_writer_cannot_delay_cancellation_restoration_or_auth_release() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.cancel = Some(Action::Login(1));
    let saving = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let persist = async {
        saving.notify_one();
        release.notified().await;
    };
    tokio::join!(
        run_owned(
            state.clone(),
            ticket,
            Arc::new(mock),
            path.0.clone(),
            persist
        ),
        async {
            saving.notified().await;
            let s = state.lock().unwrap();
            assert!(!s.auth_busy);
            assert!(s.diagnostics.status == RunStatus::Cancelled);
            assert!(s
                .diagnostics
                .report
                .contains("PASS restore original_state_confirmed"));
            drop(s);
            release.notify_one();
        }
    );
}

#[tokio::test]
async fn restore_worker_panic_reports_restore_failed_and_keeps_the_original_target() {
    let (state, ticket, mut mock, path) = setup(Baseline::Online(0));
    mock.panic_restore = true;
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    drop(backend);
    let s = state.lock().unwrap();
    assert!(s.diagnostics.status == RunStatus::RestoreFailed);
    assert_eq!(s.reconnect_targets, vec![0]);
    assert!(!s.auth_busy);
    assert!(s
        .diagnostics
        .report
        .contains("FAIL restore restore_worker_interrupted"));
}

#[tokio::test]
async fn restored_current_account_needs_no_extra_logout_or_login() {
    let (state, mut ticket, mock, path) = setup(Baseline::Online(0));
    ticket.selected_account = 0;
    let backend = Arc::new(mock);
    execute(state.clone(), ticket, backend.clone(), path.0.clone()).await;
    assert_eq!(
        *backend.actions.lock().unwrap(),
        vec![
            Action::Logout(0),
            Action::Login(0),
            Action::Logout(0),
            Action::Reconnect(0)
        ]
    );
    assert!(state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("PASS restore original_state_confirmed"));
}
