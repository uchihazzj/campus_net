//! Disruptive tests, started only through the explicit functional-test UI mode.
use std::future::Future;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use super::probes::{Backend as ProbeBackend, Check, Target};
use super::{DiagnosticMode, FunctionalPhase, RunStatus, SharedState, Ticket};
use crate::service::auth::DiagnosticSession;
use crate::service::online_info::{match_account, MatchResult};

const TEST_BUDGET: Duration = Duration::from_secs(300);
const RESTORE_BUDGET: Duration = Duration::from_secs(150);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthEvent {
    LoginStart,
    LoginAccepted,
    LoginFailed,
    LogoutStart,
    LogoutOk,
    LogoutFailed,
    RecoveryStart,
    RecoveryLogoutOk,
    RecoveryLogoutFailed,
    RecoveryRetry,
    RecoverySucceeded,
    RecoveryFailed,
    SwitchCleanup,
}

impl AuthEvent {
    fn code(self) -> &'static str {
        match self {
            Self::LoginStart => "login_start",
            Self::LoginAccepted => "portal_accepted",
            Self::LoginFailed => "login_failed",
            Self::LogoutStart => "logout_start",
            Self::LogoutOk => "logout_ok",
            Self::LogoutFailed => "logout_failed",
            Self::RecoveryStart => "recovery_all_accounts_begin",
            Self::RecoveryLogoutOk => "cleanup_account_ok",
            Self::RecoveryLogoutFailed => "cleanup_account_failed",
            Self::RecoveryRetry => "recovery_retry",
            Self::RecoverySucceeded => "recovery_succeeded",
            Self::RecoveryFailed => "recovery_failed",
            Self::SwitchCleanup => "switch_all_accounts_begin",
        }
    }
}

pub(crate) fn auth_event(
    state: &SharedState,
    account: usize,
    event: AuthEvent,
    error: Option<&str>,
) {
    let mut s = state.lock().unwrap();
    let d = &mut s.diagnostics;
    if !d.running() || d.mode != DiagnosticMode::Functional || d.phase == FunctionalPhase::None {
        return;
    }
    if d.auth_events >= 96 {
        d.auth_events_dropped += 1;
        return;
    }
    d.auth_events += 1;
    if matches!(
        event,
        AuthEvent::LoginFailed
            | AuthEvent::LogoutFailed
            | AuthEvent::RecoveryFailed
            | AuthEvent::RecoveryLogoutFailed
    ) {
        d.issues += 1;
    }
    let error = error
        .map(Failure::from_text)
        .map(|failure| failure.details())
        .unwrap_or_default();
    d.report.push_str(&format!(
        "EVENT A{} {}{}\n",
        account + 1,
        event.code(),
        error
    ));
    drop(s);
    crate::service::request_ui_repaint();
}

#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    err_code: Option<u32>,
}

impl Failure {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            err_code: None,
        }
    }
    fn from_text(message: &str) -> Self {
        let lower = message.to_ascii_lowercase();
        let err_code = lower.find("err_code").and_then(|offset| {
            let tail = lower[offset + "err_code".len()..]
                .trim_start_matches([' ', '\t', '=', ':', '\'', '"']);
            let number: String = tail
                .chars()
                .take_while(char::is_ascii_digit)
                .take(10)
                .collect();
            number.parse().ok()
        });
        let code = if err_code.is_some() {
            "server_rejected"
        } else if lower.contains("context_changed") {
            "context_changed"
        } else if lower.contains("reconnect_policy_wait") {
            "reconnect_policy_wait"
        } else if lower.contains("password") || lower.contains("decrypt") {
            "credentials"
        } else if lower.contains("decode") || lower.contains("encoding") {
            "decode_failed"
        } else if lower.contains("json") || lower.contains("challenge") {
            "protocol_format"
        } else if lower.contains("timeout") || lower.contains("timed out") {
            "timeout"
        } else if lower.contains("request") || lower.contains("connect") {
            "network_error"
        } else {
            "operation_failed"
        };
        Self { code, err_code }
    }
    fn details(self) -> String {
        format!(
            " category={}{}",
            self.code,
            self.err_code
                .map(|code| format!(" err_code={code}"))
                .unwrap_or_default()
        )
    }
    fn check(self) -> Check {
        Check {
            verdict: "FAIL",
            code: self.code,
            details: self.details(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Baseline {
    Offline,
    Online(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Logout(usize),
    Login(usize),
    Reconnect(usize),
}

trait Backend: ProbeBackend + Send + Sync + 'static {
    fn preflight(&self) -> impl Future<Output = Result<Baseline, Failure>> + Send;
    fn action(&self, action: Action) -> impl Future<Output = Result<(), Failure>> + Send;
    fn confirm(&self, expected: Option<usize>) -> impl Future<Output = Result<(), Failure>> + Send;
}

struct Network {
    state: SharedState,
    ticket: Ticket,
    session: Arc<DiagnosticSession>,
}

impl ProbeBackend for Network {
    async fn probe(&self, target: Target) -> Check {
        super::probes::Network {
            state: &self.state,
            ticket: &self.ticket,
        }
        .probe(target)
        .await
    }
    async fn sessions(
        &self,
        index: usize,
    ) -> Result<Vec<std::net::IpAddr>, crate::service::online_sessions::QueryError> {
        super::probes::Network {
            state: &self.state,
            ticket: &self.ticket,
        }
        .sessions(index)
        .await
    }
}

impl Network {
    async fn query(
        &self,
        source: Ipv4Addr,
    ) -> Result<Option<crate::service::OnlineUserInfo>, Failure> {
        if !self.session.current() {
            return Err(Failure::new("context_changed"));
        }
        let info = crate::service::online_info::fetch_online_user_info(
            &self.ticket.config.server,
            Some(&source.to_string()),
        )
        .await
        .map_err(|message| Failure::from_text(&message))?;
        if let Some(info) = &info {
            if info.online_ip.parse::<Ipv4Addr>().ok() != Some(source) {
                return Err(Failure::new("source_mismatch"));
            }
            if !matches!(
                match_account(&info.user_name, &self.ticket.config.users),
                MatchResult::Exact(_) | MatchResult::UniqueBase(_)
            ) {
                return Err(Failure::new("unknown_online_account"));
            }
        }
        Ok(info)
    }
}

fn credentials_readable(user: &crate::service::config::StoredUser) -> bool {
    !user.username.trim().is_empty()
        && crate::platform::secure_store::decrypt_password(&user.encrypted_password)
            .is_ok_and(|password| !password.is_empty())
}

impl Backend for Network {
    async fn preflight(&self) -> Result<Baseline, Failure> {
        if self.ticket.config.users.len() > super::MAX_ACCOUNTS {
            return Err(Failure::new("too_many_accounts"));
        }
        let target = self
            .ticket
            .config
            .users
            .get(self.ticket.selected_account)
            .ok_or(Failure::new("no_test_account"))?;
        if !credentials_readable(target) {
            return Err(Failure::new("credentials"));
        }
        let source = self
            .ticket
            .source
            .ok_or(Failure::new("no_cached_campus_source"))?;
        let target = target.clone();
        let resolved =
            tokio::task::spawn_blocking(move || crate::service::user_ip::resolve_login_ip(&target))
                .await
                .map_err(|_| Failure::new("interface_lookup"))?;
        if resolved.parse::<Ipv4Addr>().ok() != Some(source) {
            return Err(Failure::new("binding_source_mismatch"));
        }
        let info = self.query(source).await?;
        let baseline = match info
            .as_ref()
            .map(|info| match_account(&info.user_name, &self.ticket.config.users))
        {
            Some(MatchResult::Exact(index) | MatchResult::UniqueBase(index)) => {
                if !self
                    .ticket
                    .config
                    .users
                    .get(index)
                    .is_some_and(credentials_readable)
                {
                    return Err(Failure::new("restore_credentials"));
                }
                if index != self.ticket.selected_account {
                    let original = self.ticket.config.users[index].clone();
                    let original_ip = tokio::task::spawn_blocking(move || {
                        crate::service::user_ip::resolve_login_ip(&original)
                    })
                    .await
                    .map_err(|_| Failure::new("interface_lookup"))?;
                    if original_ip.parse::<Ipv4Addr>().ok() != Some(source) {
                        return Err(Failure::new("restore_binding_source_mismatch"));
                    }
                }
                Baseline::Online(index)
            }
            None => Baseline::Offline,
            _ => return Err(Failure::new("unknown_online_account")),
        };
        if !self.session.apply_confirmation(info) {
            return Err(Failure::new("context_changed"));
        }
        Ok(baseline)
    }

    async fn action(&self, action: Action) -> Result<(), Failure> {
        let result = match action {
            Action::Logout(index) => self.session.logout(index).await,
            Action::Login(index) => self.session.login(index, false).await,
            Action::Reconnect(index) => self.session.login(index, true).await,
        };
        result.map_err(|message| Failure::from_text(&message))
    }

    async fn confirm(&self, expected: Option<usize>) -> Result<(), Failure> {
        let mut failure = Failure::new("server_not_confirmed");
        for _ in 0..3 {
            let source = expected
                .and_then(|index| {
                    self.state
                        .lock()
                        .unwrap()
                        .user_statuses
                        .get(index)
                        .and_then(|status| status.current_ip.parse::<Ipv4Addr>().ok())
                })
                .or(self.ticket.source)
                .ok_or(Failure::new("no_cached_campus_source"))?;
            match self.query(source).await {
                Ok(info) => {
                    let actual = info.as_ref().and_then(|info| {
                        match match_account(&info.user_name, &self.ticket.config.users) {
                            MatchResult::Exact(index) | MatchResult::UniqueBase(index) => {
                                Some(index)
                            }
                            _ => None,
                        }
                    });
                    if !self.session.apply_confirmation(info) {
                        return Err(Failure::new("context_changed"));
                    }
                    if actual == expected {
                        return Ok(());
                    }
                    failure = Failure::new("unexpected_session");
                }
                Err(error) => failure = error,
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(failure)
    }
}

pub(super) fn start(state: SharedState) {
    let Some(mut ticket) = super::claim(&state) else {
        return;
    };
    // Reserve synchronously before returning to egui, so other controls cannot
    // start an authentication operation between test steps or during restore.
    let session = DiagnosticSession::begin(&state);
    if session.is_some() {
        let mut s = state.lock().unwrap();
        ticket.generation = s.auth_generation;
        s.diagnostics.phase = FunctionalPhase::Testing;
    }
    crate::service::request_ui_repaint();
    tokio::spawn(async move {
        let path = crate::path::diagnostic_path();
        let Some(session) = session else {
            state.lock().unwrap().diagnostics.report = super::header(&ticket);
            super::record(
                &state,
                ticket.id,
                "functional",
                Check::fail("auth_busy"),
                Duration::ZERO,
                &path,
            )
            .await;
            super::finish(
                &state,
                ticket.id,
                RunStatus::Interrupted,
                Duration::ZERO,
                &path,
            )
            .await;
            super::save(&state, ticket.id, &path).await;
            return;
        };
        let backend = Arc::new(Network {
            state: state.clone(),
            ticket: ticket.clone(),
            session: Arc::new(session),
        });
        let id = ticket.id;
        let persist = async {
            super::save(&state, id, &path).await;
        };
        run_owned(state.clone(), ticket, backend, path.clone(), persist).await;
    });
}

async fn run_owned<B: Backend>(
    state: SharedState,
    ticket: Ticket,
    backend: Arc<B>,
    path: PathBuf,
    persist: impl Future<Output = ()>,
) {
    let id = ticket.id;
    let started = Instant::now();
    let task = tokio::spawn(execute(
        state.clone(),
        ticket,
        backend.clone(),
        path.clone(),
    ));
    if task.await.is_err() {
        super::record(
            &state,
            id,
            "functional",
            Check::fail("worker_interrupted"),
            started.elapsed(),
            &path,
        )
        .await;
        super::finish(&state, id, RunStatus::Interrupted, started.elapsed(), &path).await;
    }
    drop(backend); // Release authentication before possibly stalled disk I/O.
    persist.await;
}

fn pass(code: &'static str) -> Check {
    Check {
        verdict: "PASS",
        code,
        details: String::new(),
    }
}

async fn action_step<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    action: (Action, &str),
    path: &std::path::Path,
    deadline: tokio::time::Instant,
    touched: &AtomicBool,
) -> Result<(), RunStatus> {
    let (action, label) = action;
    let started = Instant::now();
    let future = async {
        touched.store(true, Ordering::SeqCst);
        backend.action(action).await
    };
    let result = super::step(
        state,
        ticket,
        deadline,
        Duration::from_secs(120),
        label,
        future,
    )
    .await;
    let check = match result {
        Ok(Ok(Ok(()))) => pass("request_accepted"),
        Ok(Ok(Err(failure))) => failure.check(),
        Ok(Err(())) => Check::fail("timeout"),
        Err(reason) => return Err(reason),
    };
    let failed = check.verdict == "FAIL";
    super::record(state, ticket.id, label, check, started.elapsed(), path).await;
    if failed {
        Err(RunStatus::Failed)
    } else {
        Ok(())
    }
}

async fn confirmation<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    expected: Option<usize>,
    label: &str,
    path: &std::path::Path,
    deadline: tokio::time::Instant,
) -> Result<(), RunStatus> {
    let started = Instant::now();
    let check = match super::step(
        state,
        ticket,
        deadline,
        Duration::from_secs(20),
        label,
        backend.confirm(expected),
    )
    .await
    {
        Ok(Ok(Ok(()))) => pass("server_confirmed"),
        Ok(Ok(Err(failure))) => failure.check(),
        Ok(Err(())) => Check::fail("timeout"),
        Err(reason) => return Err(reason),
    };
    let failed = check.verdict == "FAIL";
    super::record(state, ticket.id, label, check, started.elapsed(), path).await;
    if failed {
        Err(RunStatus::Failed)
    } else {
        Ok(())
    }
}

async fn run_actions<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    baseline: Baseline,
    path: &std::path::Path,
    touched: &AtomicBool,
) -> RunStatus {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;
    let target = ticket.selected_account;
    let first_logout = match baseline {
        Baseline::Online(index) => index,
        Baseline::Offline => target,
    };
    let result = async {
        action_step(
            state,
            ticket,
            backend,
            (Action::Logout(first_logout), "logout"),
            path,
            deadline,
            touched,
        )
        .await?;
        confirmation(
            state,
            ticket,
            backend,
            None,
            "logout_confirm",
            path,
            deadline,
        )
        .await?;
        action_step(
            state,
            ticket,
            backend,
            (Action::Login(target), "login"),
            path,
            deadline,
            touched,
        )
        .await?;
        confirmation(
            state,
            ticket,
            backend,
            Some(target),
            "login_confirm",
            path,
            deadline,
        )
        .await?;
        if ticket.config.auto_reconnect {
            action_step(
                state,
                ticket,
                backend,
                (Action::Logout(target), "simulate_offline"),
                path,
                deadline,
                touched,
            )
            .await?;
            confirmation(
                state,
                ticket,
                backend,
                None,
                "offline_confirm",
                path,
                deadline,
            )
            .await?;
            action_step(
                state,
                ticket,
                backend,
                (Action::Reconnect(target), "reconnect"),
                path,
                deadline,
                touched,
            )
            .await?;
            confirmation(
                state,
                ticket,
                backend,
                Some(target),
                "reconnect_confirm",
                path,
                deadline,
            )
            .await?;
        } else {
            super::record(
                state,
                ticket.id,
                "reconnect",
                Check::skip("disabled_by_config"),
                Duration::ZERO,
                path,
            )
            .await;
        }
        Ok::<(), RunStatus>(())
    }
    .await;
    result.err().unwrap_or(RunStatus::Completed)
}

async fn restore<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    baseline: Baseline,
    path: &std::path::Path,
) -> bool {
    {
        let mut s = state.lock().unwrap();
        s.diagnostics.phase = FunctionalPhase::Restoring;
        s.diagnostics.step = "restore_original_state".into();
        for status in &mut s.user_statuses {
            if matches!(
                status.state,
                crate::service::LoginState::LoggingIn | crate::service::LoginState::LoggingOut
            ) {
                status.state = crate::service::LoginState::Error;
                status.last_error = "Diagnostic step stopped before completion".into();
            }
        }
    }
    crate::service::request_ui_repaint();
    let started = Instant::now();
    // Cancellation stops tests, then waits for this bounded restoration attempt.
    let restore = async {
        match baseline {
            Baseline::Online(index) => {
                if backend.confirm(Some(index)).await.is_ok() {
                    return Ok(());
                }
                backend
                    .action(Action::Logout(ticket.selected_account))
                    .await?;
                if let Err(failure) = backend.confirm(None).await {
                    if backend.confirm(Some(index)).await.is_ok() {
                        return Ok(());
                    }
                    return Err(failure);
                }
                backend.action(Action::Login(index)).await?;
                backend.confirm(Some(index)).await
            }
            Baseline::Offline => {
                backend
                    .action(Action::Logout(ticket.selected_account))
                    .await?;
                backend.confirm(None).await
            }
        }
    };
    let check = match tokio::time::timeout(RESTORE_BUDGET, restore).await {
        Ok(Ok(())) => pass("original_state_confirmed"),
        Ok(Err(failure)) => failure.check(),
        Err(_) => Check::fail("restore_timeout"),
    };
    let restored = check.verdict == "PASS";
    super::record(state, ticket.id, "restore", check, started.elapsed(), path).await;
    restored
}

async fn execute<B: Backend>(state: SharedState, ticket: Ticket, backend: Arc<B>, path: PathBuf) {
    let started = Instant::now();
    state.lock().unwrap().diagnostics.report = super::header(&ticket);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let baseline = match super::step(
        &state,
        &ticket,
        deadline,
        Duration::from_secs(25),
        "preflight",
        backend.preflight(),
    )
    .await
    {
        Ok(Ok(Ok(baseline))) => baseline,
        error => {
            let (outcome, check) = match error {
                Ok(Ok(Err(failure))) => (RunStatus::Failed, failure.check()),
                Err(reason) => (reason, Check::skip("stopped_before_changes")),
                _ => (RunStatus::TimedOut, Check::fail("preflight_timeout")),
            };
            super::record(
                &state,
                ticket.id,
                "preflight",
                check,
                started.elapsed(),
                &path,
            )
            .await;
            super::finish(&state, ticket.id, outcome, started.elapsed(), &path).await;
            return;
        }
    };
    let description = match baseline {
        Baseline::Online(index) => format!(
            " original=A{} test=A{}",
            index + 1,
            ticket.selected_account + 1
        ),
        Baseline::Offline => format!(" original=offline test=A{}", ticket.selected_account + 1),
    };
    super::record(
        &state,
        ticket.id,
        "preflight",
        Check {
            verdict: "PASS",
            code: "restore_plan_ready",
            details: description,
        },
        started.elapsed(),
        &path,
    )
    .await;
    let readonly = super::run_plan(
        &state,
        &ticket,
        backend.as_ref(),
        &path,
        tokio::time::Instant::now() + super::NETWORK_BUDGET,
    )
    .await;
    if readonly != RunStatus::Completed {
        super::finish(&state, ticket.id, readonly, started.elapsed(), &path).await;
        return;
    }
    let touched = Arc::new(AtomicBool::new(false));
    let worker = {
        let (state, ticket, backend, path, touched) = (
            state.clone(),
            ticket.clone(),
            backend.clone(),
            path.clone(),
            touched.clone(),
        );
        tokio::spawn(async move {
            run_actions(&state, &ticket, backend.as_ref(), baseline, &path, &touched).await
        })
    };
    let mut outcome = worker.await.unwrap_or(RunStatus::Interrupted);
    let restored = if touched.load(Ordering::SeqCst) {
        let (state, ticket, backend, path) =
            (state.clone(), ticket.clone(), backend.clone(), path.clone());
        let context = (state.clone(), ticket.id, path.clone());
        match tokio::spawn(async move {
            restore(&state, &ticket, backend.as_ref(), baseline, &path).await
        })
        .await
        {
            Ok(restored) => restored,
            Err(_) => {
                super::record(
                    &context.0,
                    context.1,
                    "restore",
                    Check::fail("restore_worker_interrupted"),
                    Duration::ZERO,
                    &context.2,
                )
                .await;
                false
            }
        }
    } else {
        true
    };
    if !restored {
        outcome = RunStatus::RestoreFailed;
        let mut s = state.lock().unwrap();
        if s.config.users == ticket.config.users && s.config.server == ticket.config.server {
            if let Baseline::Online(index) = baseline {
                s.reconnect_targets = vec![index];
            }
        }
    }
    super::record(
        &state,
        ticket.id,
        "monitor_timer",
        Check::skip("uses_policy_and_auto_login_core_without_waiting_monitor_tick"),
        Duration::ZERO,
        &path,
    )
    .await;
    let recovery_seen = state
        .lock()
        .unwrap()
        .diagnostics
        .report
        .contains("recovery_all_accounts_begin");
    if !recovery_seen {
        super::record(
            &state,
            ticket.id,
            "failure_recovery",
            Check::skip("not_triggered_no_wrong_password_injected"),
            Duration::ZERO,
            &path,
        )
        .await;
    }
    super::finish(&state, ticket.id, outcome, started.elapsed(), &path).await;
}

#[cfg(test)]
mod tests;
