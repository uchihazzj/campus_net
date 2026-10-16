//! Account-wide self-service display only. Never calls campus login/logout or recovery.
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use reqwest::Url;

use super::config::{AppConfig, StoredUser};
use super::{AppState, SharedState};

mod client;
mod parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    NotConfigured,
    Credentials,
    Network,
    Authentication,
    AccountMismatch,
    Parse,
    Pagination,
    Redirect,
    TooLarge,
    Interrupted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum QueryStatus {
    #[default]
    NotLoaded,
    Loading,
    Ready,
    Failed(QueryError),
}

#[derive(Clone, Default)]
pub struct AccountSessions {
    pub ips: Option<Vec<IpAddr>>,
    pub status: QueryStatus,
    pub updated_at: String,
    last_attempt: Option<Instant>,
    request_id: u64,
}

pub fn interval(config: &AppConfig) -> Duration {
    Duration::from_secs(config.online_sessions_interval_mins.clamp(1, 1440) * 60)
}

fn service_base(config: &AppConfig) -> Result<Url, QueryError> {
    let explicit = config.self_service_url.trim();
    let value = if explicit.is_empty() {
        // Do not silently send another school's credentials to BIT's endpoint.
        if crate::core::srun::SrunClient::normalize_server_url(&config.server).trim_end_matches('/')
            != "http://10.0.0.55"
        {
            return Err(QueryError::NotConfigured);
        }
        "http://10.0.0.54:8800"
    } else {
        explicit
    };
    let url = Url::parse(value).map_err(|_| QueryError::NotConfigured)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(QueryError::NotConfigured);
    }
    Ok(url)
}

pub(super) fn cached_source(s: &AppState) -> Option<Ipv4Addr> {
    let parse = |value: &str| {
        value
            .trim()
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|ip| ip.octets()[0] == 10)
    };
    s.current_online_info()
        .and_then(|info| parse(&info.online_ip))
        .or_else(|| s.campus_ip.as_deref().and_then(parse))
}

#[derive(Clone)]
struct Ticket {
    index: usize,
    user: StoredUser,
    base: Url,
    source: Ipv4Addr,
    auth_generation: u64,
    request_id: u64,
}

impl Ticket {
    fn context_matches(&self, s: &AppState) -> bool {
        s.config.enable_online_sessions
            && !s.authentication_busy()
            && s.config.users.get(self.index) == Some(&self.user)
            && s.auth_generation == self.auth_generation
            && service_base(&s.config).ok().as_ref() == Some(&self.base)
            && cached_source(s) == Some(self.source)
    }

    fn owns_result(&self, s: &AppState) -> bool {
        s.config.users.get(self.index) == Some(&self.user)
            && s.online_sessions.get(self.index).is_some_and(|entry| {
                entry.request_id == self.request_id && entry.status == QueryStatus::Loading
            })
    }
}

fn claim(state: &SharedState, index: usize, now: Instant) -> Option<Ticket> {
    let mut s = state.lock().unwrap();
    if !s.config.enable_online_sessions || s.authentication_busy() || s.diagnostics.running() {
        return None;
    }
    let user = s.config.users.get(index)?.clone();
    let entry = s.online_sessions.get(index)?;
    if entry.status == QueryStatus::Loading
        || entry
            .last_attempt
            .is_some_and(|last| now.saturating_duration_since(last) < interval(&s.config))
    {
        return None;
    }
    let source = cached_source(&s)?;
    let base = match service_base(&s.config) {
        Ok(base) => base,
        Err(error) => {
            let entry = s.online_sessions.get_mut(index)?;
            entry.status = QueryStatus::Failed(error);
            entry.last_attempt = Some(now);
            drop(s);
            super::request_ui_repaint();
            return None;
        }
    };
    s.online_sessions_sequence = s.online_sessions_sequence.wrapping_add(1);
    let ticket = Ticket {
        index,
        user,
        base,
        source,
        auth_generation: s.auth_generation,
        request_id: s.online_sessions_sequence,
    };
    let entry = &mut s.online_sessions[index];
    entry.request_id = ticket.request_id;
    entry.status = QueryStatus::Loading;
    entry.last_attempt = Some(now);
    drop(s);
    super::request_ui_repaint();
    Some(ticket)
}

fn complete(state: &SharedState, ticket: &Ticket, result: Result<Vec<IpAddr>, QueryError>) {
    let mut s = state.lock().unwrap();
    if !ticket.owns_result(&s) {
        return;
    }
    let current = ticket.context_matches(&s);
    let failure = result.as_ref().err().copied();
    let entry = &mut s.online_sessions[ticket.index];
    if !current {
        *entry = AccountSessions::default();
    } else {
        match result {
            Ok(ips) => {
                entry.ips = Some(ips);
                entry.status = QueryStatus::Ready;
                entry.updated_at = chrono::Local::now().format("%H:%M").to_string();
            }
            Err(error) => entry.status = QueryStatus::Failed(error),
        }
    }
    if let Some(error) = failure.filter(|_| current) {
        // Enum categories only: never include account, URL, response or credentials.
        tracing::warn!("[OnlineIPs] Query failed: {:?}", error);
        s.add_log(format!("[WARN] Online IP query failed: {error:?}"));
    }
    drop(s);
    super::request_ui_repaint();
}

struct QueryGuard {
    state: SharedState,
    ticket: Ticket,
    completed: bool,
}

impl QueryGuard {
    fn finish(mut self, result: Result<Vec<IpAddr>, QueryError>) {
        complete(&self.state, &self.ticket, result);
        self.completed = true;
    }
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        if !self.completed && !std::thread::panicking() {
            complete(&self.state, &self.ticket, Err(QueryError::Interrupted));
        }
    }
}

struct CheckedTransport<'a> {
    client: &'a reqwest::Client,
    state: &'a SharedState,
    ticket: &'a Ticket,
}

impl client::Transport for CheckedTransport<'_> {
    async fn get(&self, url: Url) -> Result<client::HttpPage, QueryError> {
        {
            let s = self.state.lock().unwrap();
            if !self.ticket.context_matches(&s) || !self.ticket.owns_result(&s) {
                return Err(QueryError::Interrupted);
            }
        }
        if !readable_request(&self.ticket.base, &url) {
            return Err(QueryError::Redirect);
        }
        client::request(self.client, url).await
    }
}

fn readable_request(base: &Url, url: &Url) -> bool {
    let sso = url.origin() == base.origin()
        && url.path() == "/site/sso"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .collect::<Vec<_>>()
            == ["data"];
    sso || parser::readable_home(base, url)
}

/// Manual diagnostics use the same parser and positive URL allowlist, but never
/// update account/auth state or the automatic query timer. Cookies stay in RAM.
pub(super) async fn diagnostic_query<F: Fn() -> bool + Sync>(
    config: &AppConfig,
    source: Ipv4Addr,
    user: &StoredUser,
    current: F,
) -> Result<Vec<IpAddr>, QueryError> {
    struct ManualTransport<'a, F> {
        client: &'a reqwest::Client,
        base: &'a Url,
        current: F,
    }
    impl<F: Fn() -> bool + Sync> client::Transport for ManualTransport<'_, F> {
        async fn get(&self, url: Url) -> Result<client::HttpPage, QueryError> {
            if !(self.current)() {
                return Err(QueryError::Interrupted);
            }
            if !readable_request(self.base, &url) {
                return Err(QueryError::Redirect);
            }
            client::request(self.client, url).await
        }
    }
    let base = service_base(config)?;
    let mut session = client::WebSession::new(source)?;
    let transport = ManualTransport {
        client: &session.client,
        base: &base,
        current,
    };
    client::load(&transport, &base, user, &mut session.authenticated).await
}

struct CachedSession {
    user: StoredUser,
    base: Url,
    source: Ipv4Addr,
    session: client::WebSession,
}

pub fn spawn_scheduler(state: SharedState) {
    tokio::spawn(async move {
        loop {
            match tokio::spawn(run_scheduler(state.clone())).await {
                Ok(()) => break,
                Err(error) if error.is_cancelled() => break,
                Err(_) => {
                    {
                        let mut s = state.lock().unwrap();
                        for entry in &mut s.online_sessions {
                            if entry.status == QueryStatus::Loading {
                                entry.status = QueryStatus::Failed(QueryError::Interrupted);
                            }
                        }
                        s.add_log("[WARN] Online IP scheduler interrupted; retry scheduled".into());
                    }
                    super::request_ui_repaint();
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}

async fn run_scheduler(state: SharedState) {
    let mut cache: Vec<CachedSession> = Vec::new();
    loop {
        let count = {
            let mut s = state.lock().unwrap();
            s.ensure_statuses();
            let base = service_base(&s.config).ok();
            let source = cached_source(&s);
            cache.retain(|entry| {
                s.config.enable_online_sessions
                    && s.config.users.contains(&entry.user)
                    && base.as_ref() == Some(&entry.base)
                    && source == Some(entry.source)
            });
            s.config.users.len()
        };
        for index in 0..count {
            let Some(ticket) = claim(&state, index, Instant::now()) else {
                continue;
            };
            let guard = QueryGuard {
                state: state.clone(),
                ticket: ticket.clone(),
                completed: false,
            };
            let position = cache.iter().position(|entry| {
                entry.user == ticket.user
                    && entry.base == ticket.base
                    && entry.source == ticket.source
            });
            let mut entry = if let Some(position) = position {
                cache.remove(position)
            } else {
                match client::WebSession::new(ticket.source) {
                    Ok(session) => CachedSession {
                        user: ticket.user.clone(),
                        base: ticket.base.clone(),
                        source: ticket.source,
                        session,
                    },
                    Err(error) => {
                        guard.finish(Err(error));
                        continue;
                    }
                }
            };
            let transport = CheckedTransport {
                client: &entry.session.client,
                state: &state,
                ticket: &ticket,
            };
            let result = tokio::time::timeout(
                Duration::from_secs(30),
                client::load(
                    &transport,
                    &ticket.base,
                    &ticket.user,
                    &mut entry.session.authenticated,
                ),
            )
            .await
            .unwrap_or(Err(QueryError::Network));
            let keep_session = !matches!(
                result,
                Err(QueryError::Authentication
                    | QueryError::AccountMismatch
                    | QueryError::Credentials)
            );
            guard.finish(result);
            if keep_session && ticket.context_matches(&state.lock().unwrap()) {
                cache.push(entry);
            }
        }
        // This tick only reads cached state; HTTP remains due at the configured interval.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests;
