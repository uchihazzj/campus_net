//! Manual diagnostics; disruptive functional tests require an explicit UI choice.
use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use super::config::AppConfig;
use super::online_sessions::{self, QueryStatus};
use super::{AppState, SharedState};

pub(crate) mod functional;
mod probes;
pub(crate) use functional::{auth_event, AuthEvent};
use probes::{Backend, Check, Network, Target};

const MAX_ACCOUNTS: usize = 16;
const NETWORK_BUDGET: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum DiagnosticMode {
    #[default]
    ReadOnly,
    Functional,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum FunctionalPhase {
    #[default]
    None,
    Testing,
    Restoring,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum RunStatus {
    #[default]
    Idle,
    Running,
    Completed,
    Cancelled,
    ContextChanged,
    TimedOut,
    Interrupted,
    Failed,
    RestoreFailed,
}

impl RunStatus {
    fn code(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::ContextChanged => "context_changed",
            Self::TimedOut => "budget_exhausted",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
            Self::RestoreFailed => "restore_failed",
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum SaveStatus {
    #[default]
    None,
    Pending,
    Saved,
    Failed,
}

#[derive(Clone, Default)]
pub struct DiagnosticState {
    pub mode: DiagnosticMode,
    pub selected_account: usize,
    pub phase: FunctionalPhase,
    pub status: RunStatus,
    pub save_status: SaveStatus,
    pub report: String,
    pub step: String,
    pub issues: usize,
    pub skipped: usize,
    cancel_requested: bool,
    sequence: u64,
    auth_events: usize,
    auth_events_dropped: usize,
    report_epoch: Arc<AtomicU64>,
}

impl DiagnosticState {
    pub fn running(&self) -> bool {
        self.status == RunStatus::Running
    }
}

pub fn can_start(s: &AppState) -> bool {
    !s.diagnostics.running()
        && !s.authentication_busy()
        && !s
            .online_sessions
            .iter()
            .any(|entry| entry.status == QueryStatus::Loading)
}

// No Debug: AppConfig contains credentials, used only in memory by self-service.
#[derive(Clone)]
struct Ticket {
    id: u64,
    config: AppConfig,
    source: Option<Ipv4Addr>,
    generation: u64,
    cache: String,
    mode: DiagnosticMode,
    selected_account: usize,
}

impl Ticket {
    fn stop_reason(&self, s: &AppState) -> Option<RunStatus> {
        if s.diagnostics.sequence != self.id || !s.diagnostics.running() {
            return Some(RunStatus::Interrupted);
        }
        if s.diagnostics.cancel_requested {
            return Some(RunStatus::Cancelled);
        }
        let owns_auth = self.mode == DiagnosticMode::Functional
            && s.diagnostics.phase != FunctionalPhase::None
            && s.auth_busy;
        if (s.authentication_busy() && !owns_auth)
            || s.auth_generation != self.generation
            || s.config.users != self.config.users
            || s.config.server != self.config.server
            || s.config.self_service_url != self.config.self_service_url
            || (!owns_auth && online_sessions::cached_source(s) != self.source)
        {
            return Some(RunStatus::ContextChanged);
        }
        None
    }

    fn current(&self, state: &SharedState) -> bool {
        self.stop_reason(&state.lock().unwrap()).is_none()
    }
}

fn claim(state: &SharedState) -> Option<Ticket> {
    let mut s = state.lock().unwrap();
    if !can_start(&s) {
        return None;
    }
    let id = s.diagnostics.sequence.wrapping_add(1);
    let report_epoch = s.diagnostics.report_epoch.clone();
    report_epoch.store(id, Ordering::SeqCst);
    let source = online_sessions::cached_source(&s);
    let source_in_cache = s.network_interfaces.as_ref().map(|interfaces| {
        source.is_some_and(|ip| interfaces.iter().any(|(_, address)| *address == ip))
    });
    let mut cache = format!(
        "cache campus_source={} source_in_cached_interfaces={:?} interfaces={} auth={:?} gateway={:?} internet={:?} auth_stale={} auth_failures={} reconnect_paused={}\n",
        source.is_some(), source_in_cache,
        s.network_interfaces.as_ref().map_or(0, Vec::len), s.campus_auth,
        s.auth_server, s.ipv4_internet, s.online_info_stale,
        s.online_info_fail_count, s.suppress_auto_reconnect,
    );
    for (index, user) in s.config.users.iter().take(MAX_ACCOUNTS).enumerate() {
        let status = s.user_statuses.get(index);
        let sessions = s.online_sessions.get(index);
        cache.push_str(&format!(
            "A{} cache local={:?} binding={} last_error_present={} online_ips={:?} cached_count={}\n",
            index + 1, status.map(|value| &value.state),
            if user.if_name.as_ref().is_some_and(|name| !name.is_empty()) { "named" }
            else if user.ip.as_ref().is_some_and(|ip| !ip.is_empty()) { "static" } else { "auto" },
            status.is_some_and(|value| !value.last_error.is_empty()),
            sessions.map(|entry| &entry.status),
            sessions.and_then(|entry| entry.ips.as_ref()).map_or(0, Vec::len),
        ));
    }
    let ticket = Ticket {
        id,
        config: s.config.clone(),
        source,
        generation: s.auth_generation,
        cache,
        mode: s.diagnostics.mode,
        selected_account: s.diagnostics.selected_account,
    };
    s.diagnostics = DiagnosticState {
        status: RunStatus::Running,
        save_status: SaveStatus::Pending,
        sequence: id,
        report_epoch,
        mode: ticket.mode,
        selected_account: ticket.selected_account,
        ..Default::default()
    };
    Some(ticket)
}

/// Called only by the explicit settings button. No startup/scheduler call site.
pub fn start(state: SharedState) {
    if state.lock().unwrap().diagnostics.mode == DiagnosticMode::Functional {
        functional::start(state);
        return;
    }
    let Some(ticket) = claim(&state) else { return };
    super::request_ui_repaint();
    tokio::spawn(async move {
        let id = ticket.id;
        let started = Instant::now();
        let path = crate::path::diagnostic_path();
        let worker_state = state.clone();
        let worker_path = path.clone();
        let worker = tokio::spawn(async move {
            let backend = Network {
                state: &worker_state,
                ticket: &ticket,
            };
            execute(
                &worker_state,
                &ticket,
                &backend,
                &worker_path,
                NETWORK_BUDGET,
            )
            .await;
        });
        if worker.await.is_err() {
            finish(&state, id, RunStatus::Interrupted, started.elapsed(), &path).await;
        }
    });
}

pub fn cancel(state: &SharedState) {
    let mut s = state.lock().unwrap();
    if s.diagnostics.running() {
        s.diagnostics.cancel_requested = true;
    }
}

fn header(ticket: &Ticket) -> String {
    let c = &ticket.config;
    format!(
        "CampusNetClient diagnostic schema=1 app={} started={}\n\
         safety={}\n\
         privacy=account_aliases,no_raw_IPs,no_credentials,no_response_bodies,no_log_dump\n\
         routing=proxy_disabled source_binding_does_not_guarantee_TUN_bypass default_route_is_not_campus_auth_evidence\n\
         config accounts={} auto_reconnect={} monitor_s={} retries={} retry_ms={} strict_bind={} double_stack={} detect_ip={} external_monitor={} online_ips={} online_ips_min={} gateway={} self_service={}\n{}",
        env!("CARGO_PKG_VERSION"), chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z"),
        if ticket.mode == DiagnosticMode::ReadOnly { "read_only interface_scan=none campus_login_logout_reconnect=never" }
        else { "functional_test manual_only campus_logout_login_reconnect=enabled restore_original_state=attempted config_changes=none" },
        c.users.len(), c.auto_reconnect, c.monitor_interval_secs, c.retry_times,
        c.retry_delay, c.strict_bind, c.double_stack, c.detect_ip,
        c.enable_ipv4_internet_probe, c.enable_online_sessions,
        c.online_sessions_interval_mins.clamp(1, 1440),
        if crate::core::srun::SrunClient::normalize_server_url(&c.server).trim_end_matches('/') == "http://10.0.0.55" { "default" } else { "custom" },
        if c.self_service_url.trim().is_empty() { "auto" } else { "explicit" },
        ticket.cache,
    )
}

async fn wait_stop(state: &SharedState, ticket: &Ticket) -> RunStatus {
    loop {
        let reason = ticket.stop_reason(&state.lock().unwrap());
        if let Some(reason) = reason {
            return reason;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn step<T>(
    state: &SharedState,
    ticket: &Ticket,
    deadline: tokio::time::Instant,
    limit: Duration,
    label: &str,
    future: impl Future<Output = T>,
) -> Result<Result<T, ()>, RunStatus> {
    state.lock().unwrap().diagnostics.step = label.to_owned();
    super::request_ui_repaint();
    // Cancellation drops in-flight HTTP futures; it never invokes any recovery.
    // https://docs.rs/tokio/1/tokio/macro.select.html#cancellation-safety
    tokio::select! {
        biased;
        reason = wait_stop(state, ticket) => Err(reason),
        _ = tokio::time::sleep_until(deadline) => Err(RunStatus::TimedOut),
        result = tokio::time::timeout(limit, future) => Ok(result.map_err(|_| ())),
    }
}

async fn record(
    state: &SharedState,
    id: u64,
    label: &str,
    check: Check,
    elapsed: Duration,
    path: &Path,
) {
    {
        let mut s = state.lock().unwrap();
        if s.diagnostics.sequence != id {
            return;
        }
        let d = &mut s.diagnostics;
        d.issues += usize::from(matches!(check.verdict, "FAIL" | "WARN"));
        d.skipped += usize::from(check.verdict == "SKIP");
        d.report.push_str(&format!(
            "{} {} {} ms={}{}\n",
            check.verdict,
            label,
            check.code,
            elapsed.as_millis(),
            check.details
        ));
    }
    super::request_ui_repaint();
    if state.lock().unwrap().diagnostics.mode == DiagnosticMode::ReadOnly {
        save(state, id, path).await;
    }
}

async fn execute<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    path: &Path,
    budget: Duration,
) {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + budget;
    state.lock().unwrap().diagnostics.report = header(ticket);
    save(state, ticket.id, path).await;
    let outcome = run_plan(state, ticket, backend, path, deadline).await;
    finish(state, ticket.id, outcome, started.elapsed(), path).await;
}

async fn run_plan<B: Backend>(
    state: &SharedState,
    ticket: &Ticket,
    backend: &B,
    path: &Path,
    deadline: tokio::time::Instant,
) -> RunStatus {
    for target in [
        Target::Gateway,
        Target::InternetBound204,
        Target::InternetBoundText,
        Target::InternetDefaultText,
    ] {
        let label = target.label();
        let started = Instant::now();
        let check = if ticket.source.is_none() && target != Target::InternetDefaultText {
            Check::skip("no_cached_campus_source")
        } else {
            match step(
                state,
                ticket,
                deadline,
                Duration::from_secs(8),
                label,
                backend.probe(target),
            )
            .await
            {
                Ok(Ok(check)) => check,
                Ok(Err(())) => Check::fail("timeout"),
                Err(reason) => return reason,
            }
        };
        record(state, ticket.id, label, check, started.elapsed(), path).await;
    }
    for index in 0..ticket.config.users.len().min(MAX_ACCOUNTS) {
        let label = format!("A{} self_service", index + 1);
        let started = Instant::now();
        let check = if ticket.source.is_none() {
            Check::skip("no_cached_campus_source")
        } else {
            match step(
                state,
                ticket,
                deadline,
                Duration::from_secs(30),
                &label,
                backend.sessions(index),
            )
            .await
            {
                Ok(Ok(Ok(ips))) => Check::sessions(&ips, ticket.source),
                Ok(Ok(Err(error))) => Check::session_error(error),
                Ok(Err(())) => Check::fail("timeout"),
                Err(reason) => return reason,
            }
        };
        record(state, ticket.id, &label, check, started.elapsed(), path).await;
    }
    if ticket.config.users.len() > MAX_ACCOUNTS {
        record(
            state,
            ticket.id,
            "self_service",
            Check {
                verdict: "SKIP",
                code: "account_limit",
                details: format!(" remaining={}", ticket.config.users.len() - MAX_ACCOUNTS),
            },
            Duration::ZERO,
            path,
        )
        .await;
    }
    ticket
        .stop_reason(&state.lock().unwrap())
        .unwrap_or(RunStatus::Completed)
}

async fn finish(state: &SharedState, id: u64, outcome: RunStatus, elapsed: Duration, path: &Path) {
    {
        let mut s = state.lock().unwrap();
        let d = &mut s.diagnostics;
        if d.sequence != id || !d.running() {
            return;
        }
        d.report.push_str(&format!(
            "end outcome={} issues={} skipped={} total_ms={} last_step={} auth_events_dropped={}\n",
            outcome.code(),
            d.issues,
            d.skipped,
            elapsed.as_millis(),
            d.step,
            d.auth_events_dropped
        ));
    }
    // Persist outside the cancellable network future so partial/final writes
    // cannot race and leave an older report on disk after cancellation.
    if state.lock().unwrap().diagnostics.mode == DiagnosticMode::ReadOnly {
        save(state, id, path).await;
    }
    {
        let mut s = state.lock().unwrap();
        if s.diagnostics.sequence == id {
            s.diagnostics.status = outcome;
        }
    }
    super::request_ui_repaint();
}

async fn save(state: &SharedState, id: u64, path: &Path) {
    let (report, epoch) = {
        let mut s = state.lock().unwrap();
        if s.diagnostics.sequence != id {
            return;
        }
        s.diagnostics.save_status = SaveStatus::Pending;
        (
            s.diagnostics.report.clone(),
            s.diagnostics.report_epoch.clone(),
        )
    };
    let path = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        write_report_current(&path, &report, || epoch.load(Ordering::SeqCst) == id)
    })
    .await;
    let mut s = state.lock().unwrap();
    if s.diagnostics.sequence == id {
        s.diagnostics.save_status = if matches!(result, Ok(Ok(()))) {
            SaveStatus::Saved
        } else {
            SaveStatus::Failed
        };
    }
    drop(s);
    super::request_ui_repaint();
}

struct TemporaryReport(PathBuf);

impl Drop for TemporaryReport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn create_temporary_report(path: &Path) -> std::io::Result<(TemporaryReport, std::fs::File)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("diagnostic-latest.txt");
    loop {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary =
            path.with_file_name(format!("{name}.tmp-{}-{sequence}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((TemporaryReport(temporary), file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
fn write_report(path: &Path, report: &str) -> std::io::Result<()> {
    write_report_current(path, report, || true)
}

fn write_report_current(
    path: &Path,
    report: &str,
    current: impl FnOnce() -> bool,
) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Each process/write owns its temporary file. The shared latest report
    // permits last-writer-wins, without mixing concurrent writers' contents.
    let (temporary, mut file) = create_temporary_report(path)?;
    file.write_all(report.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // Only background writers take this lock. No AppState/UI lock crosses I/O.
    static COMMIT: Mutex<()> = Mutex::new(());
    let _commit = COMMIT.lock().unwrap_or_else(|error| error.into_inner());
    if !current() {
        return Ok(());
    }
    std::fs::rename(&temporary.0, path)
}

#[cfg(test)]
mod tests;
