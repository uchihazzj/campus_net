//! Synthetic backends only: no sockets, native app, runtime config or ProgramData.
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use super::probes::{Backend, Check, Target};
use super::*;
use crate::service::{
    config::StoredUser, AuthServerStatus, CampusAuthStatus, LoginState, OnlineUserInfo,
};

pub(in crate::service::diagnostics) fn fixture() -> SharedState {
    let config = AppConfig {
        users: vec![StoredUser {
            username: "fixture-account-SECRET".into(),
            encrypted_password: "fixture-encrypted-SECRET".into(),
            ip: Some("10.9.8.7".into()),
            if_name: Some("fixture-interface-SECRET".into()),
        }],
        ..Default::default()
    };
    let mut s = AppState::new(config);
    s.campus_ip = Some("10.9.8.7".into());
    s.network_interfaces = Some(vec![(
        "fixture-interface-SECRET".into(),
        "10.9.8.7".parse().unwrap(),
    )]);
    s.auth_server = AuthServerStatus::Reachable;
    s.campus_auth = CampusAuthStatus::LoggedIn;
    s.user_statuses[0].state = LoginState::Online;
    s.user_statuses[0].last_error = "fixture-error-SECRET".into();
    s.online_info = Some(OnlineUserInfo {
        error: "ok".into(),
        user_name: s.config.users[0].username.clone(),
        online_ip: "10.9.8.7".into(),
        ..Default::default()
    });
    s.log_messages.push("fixture-noisy-log-SECRET".into());
    Arc::new(Mutex::new(s))
}

fn auth_snapshot(state: &SharedState) -> String {
    let s = state.lock().unwrap();
    format!(
        "{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{:?}",
        serde_json::to_string(&s.config).unwrap(),
        s.user_statuses,
        s.online_info,
        s.network_interfaces,
        s.auth_server,
        s.campus_auth,
        s.ipv4_internet,
        s.reconnect_targets,
        s.auth_busy,
        s.auth_generation,
        s.online_query_generation,
        s.online_query_busy,
        s.suppress_auto_reconnect,
        s.internet_fail_count,
        s.online_info_fail_count,
        s.online_info_stale,
        s.online_sessions_sequence,
        s.log_messages
    )
}

pub(in crate::service::diagnostics) struct ReportPath(pub(in crate::service::diagnostics) PathBuf);
impl ReportPath {
    pub(in crate::service::diagnostics) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(
            std::env::temp_dir()
                .join(format!(
                    "cnet-diagnostic-fixture-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ))
                .join("report.txt"),
        )
    }
}
impl Drop for ReportPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir(self.0.parent().unwrap());
    }
}

#[derive(Default)]
struct Mock {
    calls: Mutex<Vec<Target>>,
    accounts: Mutex<Vec<usize>>,
    pending: bool,
    failed: bool,
    started: tokio::sync::Notify,
}
impl Backend for Mock {
    async fn probe(&self, target: Target) -> Check {
        self.calls.lock().unwrap().push(target);
        self.started.notify_one();
        if self.pending {
            return std::future::pending().await;
        }
        if self.failed {
            Check::fail("connect_failed")
        } else {
            Check {
                verdict: "PASS",
                code: "fixture_response",
                details: String::new(),
            }
        }
    }
    async fn sessions(&self, index: usize) -> Result<Vec<IpAddr>, online_sessions::QueryError> {
        self.accounts.lock().unwrap().push(index);
        if self.failed {
            Err(online_sessions::QueryError::Authentication)
        } else {
            Ok(vec![
                "10.9.8.7".parse().unwrap(),
                "10.9.8.8".parse().unwrap(),
            ])
        }
    }
}

#[tokio::test]
async fn full_run_is_compact_private_persistent_and_does_not_mutate_auth() {
    let state = fixture();
    let before = auth_snapshot(&state);
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock::default();
    execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)).await;
    assert_eq!(auth_snapshot(&state), before);
    let s = state.lock().unwrap();
    assert!(s.diagnostics.status == RunStatus::Completed);
    assert!(s.diagnostics.save_status == SaveStatus::Saved);
    assert_eq!(s.diagnostics.issues, 0);
    assert!(s.diagnostics.report.len() < 2500);
    assert!(s.diagnostics.report.contains("A1 self_service list_parsed"));
    assert!(s.diagnostics.report.contains("count=2 source_present=true"));
    assert!(!s.diagnostics.report.contains("SECRET"));
    assert!(!s.diagnostics.report.contains("10.9.8."));
    assert_eq!(
        std::fs::read_to_string(&path.0).unwrap(),
        s.diagnostics.report
    );
    assert_eq!(backend.calls.lock().unwrap().len(), 4);
    assert_eq!(*backend.accounts.lock().unwrap(), vec![0]);
}

#[tokio::test]
async fn failed_checks_continue_without_login_cleanup_or_reconnect() {
    let state = fixture();
    let before = auth_snapshot(&state);
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock {
        failed: true,
        ..Default::default()
    };
    execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)).await;
    assert_eq!(auth_snapshot(&state), before);
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.status == RunStatus::Completed);
    assert_eq!(d.issues, 5);
    assert!(d.report.contains("category=Authentication"));
    assert!(d.report.contains("end outcome=completed issues=5"));
}

#[tokio::test]
async fn cancellation_keeps_partial_results_and_releases_manual_guard() {
    let state = fixture();
    let before = auth_snapshot(&state);
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock {
        pending: true,
        ..Default::default()
    };
    tokio::join!(
        execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)),
        async {
            backend.started.notified().await;
            cancel(&state);
        }
    );
    assert_eq!(auth_snapshot(&state), before);
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.status == RunStatus::Cancelled);
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
    assert!(d.report.contains("outcome=cancelled"));
    assert_eq!(std::fs::read_to_string(&path.0).unwrap(), d.report);
    assert!(can_start(&state.lock().unwrap()));
}

#[tokio::test]
async fn changed_context_stops_before_the_next_network_request() {
    let state = fixture();
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock {
        pending: true,
        ..Default::default()
    };
    tokio::join!(
        execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)),
        async {
            backend.started.notified().await;
            state.lock().unwrap().invalidate_auth_context();
        }
    );
    assert!(state.lock().unwrap().diagnostics.status == RunStatus::ContextChanged);
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
    assert!(backend.accounts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn network_budget_stops_pending_http_and_preserves_a_report() {
    let state = fixture();
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock {
        pending: true,
        ..Default::default()
    };
    execute(
        &state,
        &ticket,
        &backend,
        &path.0,
        Duration::from_millis(10),
    )
    .await;
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.status == RunStatus::TimedOut);
    assert!(d.report.contains("outcome=budget_exhausted"));
    assert!(d.report.contains("last_step=gateway_bound"));
    assert_eq!(std::fs::read_to_string(&path.0).unwrap(), d.report);
}

#[tokio::test]
async fn absent_source_only_tests_default_route_and_reports_skipped_coverage() {
    let state = fixture();
    {
        let mut s = state.lock().unwrap();
        s.campus_ip = None;
        s.online_info = None;
    }
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock::default();
    execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)).await;
    let d = state.lock().unwrap().diagnostics.clone();
    assert_eq!(d.skipped, 4);
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec![Target::InternetDefaultText]
    );
    assert!(backend.accounts.lock().unwrap().is_empty());
    assert!(d
        .report
        .contains("default_route_is_not_campus_auth_evidence"));
}

#[tokio::test]
async fn report_write_failure_retains_copyable_results() {
    let state = fixture();
    let path = ReportPath::new();
    std::fs::create_dir_all(path.0.parent().unwrap()).unwrap();
    std::fs::write(&path.0, "fixture-blocks-child-path").unwrap();
    let ticket = claim(&state).unwrap();
    execute(
        &state,
        &ticket,
        &Mock::default(),
        &path.0.join("child.txt"),
        Duration::from_secs(5),
    )
    .await;
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.save_status == SaveStatus::Failed);
    assert!(d.status == RunStatus::Completed);
    assert!(d.report.contains("end outcome=completed"));
}

#[test]
fn only_one_run_can_claim_idle_auth_and_self_service_state() {
    let state = fixture();
    state.lock().unwrap().auth_busy = true;
    assert!(claim(&state).is_none());
    state.lock().unwrap().auth_busy = false;
    state.lock().unwrap().online_sessions[0].status = QueryStatus::Loading;
    assert!(claim(&state).is_none());
    state.lock().unwrap().online_sessions[0].status = QueryStatus::NotLoaded;
    assert!(claim(&state).is_some());
    assert!(claim(&state).is_none());
}

#[test]
fn saving_replaces_only_the_latest_report_instead_of_growing_history() {
    let path = ReportPath::new();
    write_report(&path.0, "first").unwrap();
    write_report(&path.0, "second").unwrap();
    assert_eq!(std::fs::read_to_string(&path.0).unwrap(), "second");
    assert_eq!(
        std::fs::read_dir(path.0.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn concurrent_report_writers_publish_one_complete_report_and_remove_their_temps() {
    let path = ReportPath::new();
    let reports: Vec<_> = (0..6)
        .map(|index| format!("fixture-writer-{index}\n").repeat(4096))
        .collect();
    let barrier = std::sync::Barrier::new(reports.len());
    std::thread::scope(|scope| {
        for report in &reports {
            scope.spawn(|| {
                barrier.wait();
                write_report(&path.0, report).unwrap();
            });
        }
    });
    let published = std::fs::read_to_string(&path.0).unwrap();
    assert!(reports.contains(&published));
    assert_eq!(
        std::fs::read_dir(path.0.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn failed_report_replacement_removes_only_its_own_temporary_file() {
    let path = ReportPath::new();
    std::fs::create_dir_all(&path.0).unwrap();
    let unrelated = path.0.parent().unwrap().join("unrelated.tmp");
    std::fs::write(&unrelated, "other-writer").unwrap();
    assert!(write_report(&path.0, "fixture-report").is_err());
    assert_eq!(
        std::fs::read_dir(path.0.parent().unwrap()).unwrap().count(),
        2
    );
    assert_eq!(std::fs::read_to_string(&unrelated).unwrap(), "other-writer");
    std::fs::remove_file(unrelated).unwrap();
    std::fs::remove_dir(&path.0).unwrap();
}

#[test]
fn delayed_report_from_an_older_run_cannot_overwrite_a_newer_report() {
    let state = fixture();
    let first = claim(&state).unwrap();
    let old_epoch = state.lock().unwrap().diagnostics.report_epoch.clone();
    state.lock().unwrap().diagnostics.status = RunStatus::Completed;
    let second = claim(&state).unwrap();
    let path = ReportPath::new();
    write_report(&path.0, "newer report").unwrap();
    write_report_current(&path.0, "stalled old report", || {
        old_epoch.load(std::sync::atomic::Ordering::SeqCst) == first.id
    })
    .unwrap();
    assert!(second.id != first.id);
    assert_eq!(std::fs::read_to_string(&path.0).unwrap(), "newer report");
}

#[tokio::test]
async fn many_accounts_have_bounded_requests_and_an_explicit_skip_count() {
    let state = fixture();
    {
        let mut s = state.lock().unwrap();
        let user = s.config.users[0].clone();
        s.config.users = vec![user; MAX_ACCOUNTS + 7];
        s.ensure_statuses();
    }
    let path = ReportPath::new();
    let ticket = claim(&state).unwrap();
    let backend = Mock::default();
    execute(&state, &ticket, &backend, &path.0, Duration::from_secs(5)).await;
    let d = state.lock().unwrap().diagnostics.clone();
    assert!(d.status == RunStatus::Completed);
    assert_eq!(backend.accounts.lock().unwrap().len(), MAX_ACCOUNTS);
    assert!(d
        .report
        .contains("SKIP self_service account_limit ms=0 remaining=7"));
    assert!(!d.report.contains("SECRET"));
}
