//! Synthetic HTTP responses and in-memory state only; no sockets or runtime config.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine;
use reqwest::StatusCode;

use super::client::{load, HttpPage, Transport};
use super::*;
use crate::service::{CampusAuthStatus, LoginState};

fn user(name: &str) -> StoredUser {
    StoredUser {
        username: name.into(),
        encrypted_password: base64::engine::general_purpose::STANDARD.encode("synthetic-password"),
        ip: None,
        if_name: None,
    }
}

fn state() -> SharedState {
    let mut s = AppState::new(AppConfig {
        users: vec![user("test-account"), user("test-other")],
        ..Default::default()
    });
    s.campus_ip = Some("10.0.0.2".into());
    Arc::new(Mutex::new(s))
}

fn base() -> Url {
    Url::parse("http://10.0.0.54:8800").unwrap()
}

fn home(rows: &str, pagination: &str) -> String {
    format!(
        r#"<html><form method="post" action="/site/logout"><input name="_csrf-8800" value="synthetic-csrf"></form>
    <table><tr><th>产品名称</th><th>已用流量</th></tr><tr><td>Fixture plan</td><td>1 GB</td></tr></table>
    <div class="grid-view"><table class="kv-grid-table"><thead><tr><th>用户名</th><th> IP 地址 </th><th>上线时间</th><th>已用流量</th><th>产品名称</th><th>计费策略</th><th>操作</th></tr></thead><tbody>{rows}</tbody></table>{pagination}</div></html>"#
    )
}

fn row(username: &str, ip: &str) -> String {
    format!(
        r#"<tr><td>{username}</td><td>{ip}</td><td>2026-01-01 10:00:00</td><td>1 GB</td><td>Fixture</td><td>Fixture</td><td><a href="/home/delete?id=synthetic&amp;user_mac=synthetic" data-method="post">下线</a></td></tr>"#
    )
}

fn html_page(body: String) -> HttpPage {
    HttpPage {
        status: StatusCode::OK,
        location: None,
        content_type: Some("text/html; charset=utf-8".into()),
        body: body.into_bytes(),
    }
}

fn redirect(location: &str) -> HttpPage {
    HttpPage {
        status: StatusCode::FOUND,
        location: Some(location.into()),
        content_type: None,
        body: Vec::new(),
    }
}

struct Mock {
    replies: Mutex<VecDeque<(&'static str, HttpPage)>>,
}

impl Mock {
    fn new(replies: Vec<(&'static str, HttpPage)>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
        }
    }
    fn exhausted(&self) {
        assert!(self.replies.lock().unwrap().is_empty());
    }
}

impl Transport for Mock {
    async fn get(&self, url: Url) -> Result<HttpPage, QueryError> {
        let (expected, reply) = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request");
        let (path, query) = expected
            .split_once('?')
            .map_or((expected, None), |(path, query)| (path, Some(query)));
        assert_eq!(url.path(), path);
        if let Some(query) = query {
            assert_eq!(url.query(), Some(query));
        }
        if path == "/site/sso" {
            assert_eq!(url.query_pairs().count(), 1);
            let (key, packet) = url.query_pairs().next().unwrap();
            assert_eq!(key, "data");
            let decoded = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(packet.as_bytes())
                    .unwrap(),
            )
            .unwrap();
            assert!(decoded.starts_with("zh-CN:test-account:"));
            assert_eq!(
                decoded,
                "zh-CN:test-account:6ee7966bfda254813a6a475e009f6780"
            );
        } else {
            assert!(parser::readable_home(&base(), &url));
        }
        Ok(reply)
    }
}

#[test]
fn parser_selects_online_table_and_validates_ownership() {
    let html = home(
        &(row("test&amp;account", "10.0.0.8") + &row("test&amp;account", "10.0.0.9")),
        "",
    );
    let parsed = parser::parse_page(&html, &base(), "test&account").unwrap();
    assert_eq!(parsed.ips.len(), 2);
    assert!(parsed.pages.is_empty());
    assert_eq!(
        parser::parse_page(&html, &base(), "test-other").err(),
        Some(QueryError::AccountMismatch)
    );
    let invalid = home(&row("test-account", "10.0.0.999"), "");
    assert_eq!(
        parser::parse_page(&invalid, &base(), "test-account").err(),
        Some(QueryError::Parse)
    );
}

#[test]
fn only_explicit_authenticated_empty_lists_are_empty() {
    let empty = home(
        r#"<tr><td colspan="7"><div class="empty">没有找到数据。</div></td></tr>"#,
        "",
    );
    assert!(parser::parse_page(&empty, &base(), "test-account")
        .unwrap()
        .ips
        .is_empty());
    for body in [
        String::new(),
        "<html>temporarily unavailable</html>".into(),
        home("", ""),
    ] {
        assert_eq!(
            parser::parse_page(&body, &base(), "test-account").err(),
            Some(QueryError::Parse)
        );
    }
    assert_eq!(
        parser::parse_page(
            "<input name='LoginForm[password]'>",
            &base(),
            "test-account"
        )
        .err(),
        Some(QueryError::Authentication)
    );
}

#[test]
fn pagination_never_allows_actions_external_hosts_or_arbitrary_queries() {
    for url in [
        "http://example.test/home?page=2",
        "http://10.0.0.54:8800/home/delete?id=1",
        "http://10.0.0.54:8800/home?action=logout",
        "http://10.0.0.54:8800/home?page=2&page=3",
        "http://10.0.0.54:8800/home?per-page=0",
        "http://10.0.0.54:8800/home?page=abc",
        "http://10.0.0.54:8800/home#logout",
    ] {
        assert!(!parser::readable_home(&base(), &Url::parse(url).unwrap()));
    }
    assert!(parser::readable_home(
        &base(),
        &base().join("/home?page=2&per-page=20").unwrap()
    ));
    let bad = home(
        &row("test-account", "10.0.0.8"),
        r#"<ul class="pagination"><li><a href="/home/onekey">Next</a></li></ul>"#,
    );
    assert_eq!(
        parser::parse_page(&bad, &base(), "test-account").err(),
        Some(QueryError::Pagination)
    );
}

#[tokio::test]
async fn sso_reads_all_discovered_pages_without_touching_action_links() {
    let pager = r#"<ul class="pagination"><li class="active"><a href="/home?page=1">1</a></li><li><a href="/home?page=2&amp;per-page=20">2</a></li></ul>"#;
    let mock = Mock::new(vec![
        ("/site/sso", redirect("/home")),
        (
            "/home",
            html_page(home(&row("test-account", "10.0.0.9"), pager)),
        ),
        (
            "/home",
            html_page(home(
                &(row("test-account", "10.0.0.8") + &row("test-account", "10.0.0.9")),
                "",
            )),
        ),
    ]);
    let mut authenticated = false;
    let ips = load(&mock, &base(), &user("test-account"), &mut authenticated)
        .await
        .unwrap();
    assert_eq!(
        ips,
        vec![
            "10.0.0.8".parse::<IpAddr>().unwrap(),
            "10.0.0.9".parse().unwrap()
        ]
    );
    assert!(authenticated);
    mock.exhausted();
}

#[tokio::test]
async fn query_only_pagination_uses_the_current_page_without_inventing_parameters() {
    let next = |href| format!(r#"<ul class="pagination"><li><a href="{href}">Next</a></li></ul>"#);
    let mock = Mock::new(vec![
        ("/site/sso", redirect("/home")),
        (
            "/home",
            html_page(home(
                &row("test-account", "10.0.0.8"),
                &next("?page=2&amp;per-page=20"),
            )),
        ),
        (
            "/home?page=2&per-page=20",
            html_page(home(&row("test-account", "10.0.0.9"), &next("?page=3"))),
        ),
        (
            "/home?page=3",
            html_page(home(&row("test-account", "10.0.0.10"), "")),
        ),
    ]);
    assert_eq!(
        load(&mock, &base(), &user("test-account"), &mut false)
            .await
            .unwrap()
            .len(),
        3
    );
    mock.exhausted();
}

#[tokio::test]
async fn excessive_pagination_is_rejected_instead_of_returning_a_partial_list() {
    let mut replies = vec![("/site/sso", redirect("/home"))];
    for page in 1..=20 {
        let next = format!(
            r#"<ul class="pagination"><li><a href="/home?page={}">Next</a></li></ul>"#,
            page + 1
        );
        replies.push((
            "/home",
            html_page(home(&row("test-account", "10.0.0.8"), &next)),
        ));
    }
    let mock = Mock::new(replies);
    assert_eq!(
        load(&mock, &base(), &user("test-account"), &mut false).await,
        Err(QueryError::Pagination)
    );
    mock.exhausted();
}

#[tokio::test]
async fn valid_web_sessions_skip_reauthentication_and_expiry_recovers_only_once() {
    let good = || html_page(home(&row("test-account", "10.0.0.8"), ""));
    let mock = Mock::new(vec![
        ("/site/sso", redirect("/home")),
        ("/home", good()),
        ("/home", good()),
        ("/home", redirect("/login")),
        ("/site/sso", redirect("/home")),
        ("/home", redirect("/login")),
    ]);
    let mut authenticated = false;
    assert!(
        load(&mock, &base(), &user("test-account"), &mut authenticated)
            .await
            .is_ok()
    );
    assert!(
        load(&mock, &base(), &user("test-account"), &mut authenticated)
            .await
            .is_ok()
    );
    assert_eq!(
        load(&mock, &base(), &user("test-account"), &mut authenticated).await,
        Err(QueryError::Authentication)
    );
    assert!(!authenticated);
    mock.exhausted();
}

#[tokio::test]
async fn unexpected_redirects_and_unreadable_credentials_never_send_other_requests() {
    let mock = Mock::new(vec![("/site/sso", redirect("http://example.test/home"))]);
    assert_eq!(
        load(&mock, &base(), &user("test-account"), &mut false).await,
        Err(QueryError::Authentication)
    );
    mock.exhausted();
    let mock = Mock::new(vec![]);
    let mut invalid = user("test-account");
    invalid.encrypted_password = "!invalid-base64!".into();
    assert_eq!(
        load(&mock, &base(), &invalid, &mut false).await,
        Err(QueryError::Credentials)
    );
    mock.exhausted();
}

#[tokio::test]
async fn chinese_gbk_html_is_decoded_before_parsing() {
    let html = home(&row("test-account", "10.0.0.8"), "");
    let (bytes, _, errors) = encoding_rs::GBK.encode(&html);
    assert!(!errors);
    let page = HttpPage {
        status: StatusCode::OK,
        location: None,
        content_type: Some("text/html; charset=gbk".into()),
        body: bytes.into_owned(),
    };
    let mock = Mock::new(vec![("/home", page)]);
    assert_eq!(
        load(&mock, &base(), &user("test-account"), &mut true)
            .await
            .unwrap()
            .len(),
        1
    );
    mock.exhausted();
}

#[test]
fn scheduler_uses_independent_five_minute_intervals_even_after_failure() {
    let state = state();
    let now = Instant::now();
    let ticket = claim(&state, 0, now).unwrap();
    assert!(claim(&state, 0, now).is_none());
    complete(&state, &ticket, Ok(vec!["10.0.0.8".parse().unwrap()]));
    assert!(claim(&state, 0, now + Duration::from_secs(299)).is_none());
    let ticket = claim(&state, 0, now + Duration::from_secs(300)).unwrap();
    {
        let mut s = state.lock().unwrap();
        s.user_statuses[0].state = LoginState::Online;
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.suppress_auto_reconnect = true;
    }
    complete(&state, &ticket, Err(QueryError::Network));
    let s = state.lock().unwrap();
    assert_eq!(s.online_sessions[0].ips.as_ref().unwrap().len(), 1);
    assert_eq!(
        s.online_sessions[0].status,
        QueryStatus::Failed(QueryError::Network)
    );
    assert_eq!(s.campus_auth, CampusAuthStatus::LoggedIn);
    assert_eq!(s.user_statuses[0].state, LoginState::Online);
    assert!(s.suppress_auto_reconnect);
    assert_eq!(s.auth_generation, 0);
    drop(s);
    assert!(claim(&state, 0, now + Duration::from_secs(301)).is_none());
}

#[test]
fn config_defaults_interval_changes_and_disabled_queries_are_bounded() {
    let config: AppConfig = serde_json::from_str("{}").unwrap();
    assert!(config.enable_online_sessions);
    assert_eq!(interval(&config), Duration::from_secs(300));
    let state = state();
    let now = Instant::now();
    let ticket = claim(&state, 0, now).unwrap();
    complete(&state, &ticket, Ok(vec![]));
    state.lock().unwrap().config.online_sessions_interval_mins = 0;
    assert!(claim(&state, 0, now + Duration::from_secs(59)).is_none());
    assert!(claim(&state, 0, now + Duration::from_secs(60)).is_some());
    state.lock().unwrap().config.enable_online_sessions = false;
    assert!(claim(&state, 1, now).is_none());
    state.lock().unwrap().config.online_sessions_interval_mins = u64::MAX;
    assert_eq!(
        interval(&state.lock().unwrap().config),
        Duration::from_secs(86400)
    );
}

#[test]
fn changed_credentials_removed_accounts_and_new_networks_reject_late_results() {
    let state = state();
    let ticket = claim(&state, 0, Instant::now()).unwrap();
    let shifted = claim(&state, 1, Instant::now()).unwrap();
    assert!(state.lock().unwrap().remove_user(0));
    complete(&state, &ticket, Ok(vec![]));
    complete(&state, &shifted, Ok(vec![]));
    assert_eq!(
        state.lock().unwrap().online_sessions[0].status,
        QueryStatus::NotLoaded
    );
    let ticket = claim(&state, 0, Instant::now()).unwrap();
    state.lock().unwrap().campus_ip = Some("10.0.0.3".into());
    complete(&state, &ticket, Ok(vec![]));
    assert_eq!(
        state.lock().unwrap().online_sessions[0].status,
        QueryStatus::NotLoaded
    );
    let ticket = claim(&state, 0, Instant::now()).unwrap();
    let mut changed = user("test-other");
    changed.encrypted_password = "synthetic-change".into();
    state.lock().unwrap().replace_user(0, changed);
    complete(&state, &ticket, Ok(vec![]));
    assert!(state.lock().unwrap().online_sessions[0].ips.is_none());
}

#[test]
fn cancelling_query_releases_only_its_display_state() {
    let state = state();
    let ticket = claim(&state, 0, Instant::now()).unwrap();
    drop(QueryGuard {
        state: state.clone(),
        ticket,
        completed: false,
    });
    let s = state.lock().unwrap();
    assert_eq!(
        s.online_sessions[0].status,
        QueryStatus::Failed(QueryError::Interrupted)
    );
    assert_eq!(s.auth_generation, 0);
    assert!(!s.auth_busy && !s.suppress_auto_reconnect);
}

#[test]
fn other_schools_require_an_explicit_service_address() {
    let mut config = AppConfig {
        server: "http://auth.example.test".into(),
        ..Default::default()
    };
    assert_eq!(service_base(&config), Err(QueryError::NotConfigured));
    config.self_service_url = "https://self.example.test".into();
    assert!(service_base(&config).is_ok());
    for invalid in [
        "http://user:password@self.example.test",
        "https://self.example.test/home",
        "https://self.example.test?data=fixture",
        "file:///home",
    ] {
        config.self_service_url = invalid.into();
        assert_eq!(service_base(&config), Err(QueryError::NotConfigured));
    }
}

#[test]
fn manual_diagnostics_defers_background_queries_without_touching_their_timers() {
    let state = state();
    state.lock().unwrap().diagnostics.status = super::super::diagnostics::RunStatus::Running;
    let before = state.lock().unwrap().online_sessions[0].last_attempt;
    assert!(claim(&state, 0, Instant::now()).is_none());
    assert_eq!(
        state.lock().unwrap().online_sessions[0].last_attempt,
        before
    );
    state.lock().unwrap().diagnostics.status = super::super::diagnostics::RunStatus::Completed;
    assert!(claim(&state, 0, Instant::now()).is_some());
}

#[tokio::test]
async fn manual_query_cancellation_stops_before_sso_transport() {
    let config = AppConfig::default();
    let result = diagnostic_query(
        &config,
        "10.0.0.2".parse().unwrap(),
        &user("fixture-manual"),
        || false,
    )
    .await;
    assert_eq!(result, Err(QueryError::Interrupted));
}

#[test]
fn manual_and_scheduled_requests_share_the_same_read_only_allowlist() {
    for path in [
        "/home/delete?id=1",
        "/home/onekey",
        "/home/manual-open",
        "/site/logout",
        "/site/sso?data=fixture&logout=1",
    ] {
        assert!(!readable_request(&base(), &base().join(path).unwrap()));
    }
    assert!(!readable_request(
        &base(),
        &Url::parse("http://external.test/home").unwrap()
    ));
    assert!(readable_request(
        &base(),
        &base().join("/site/sso?data=fixture").unwrap()
    ));
    assert!(readable_request(
        &base(),
        &base().join("/home?page=2").unwrap()
    ));
}
