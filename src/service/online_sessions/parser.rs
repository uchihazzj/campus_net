use std::net::IpAddr;

use reqwest::Url;
use scraper::{ElementRef, Html, Selector};

use super::QueryError;

pub(super) struct SessionPage {
    pub ips: Vec<IpAddr>,
    pub pages: Vec<Url>,
}

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("static self-service selector")
}

fn text(element: ElementRef<'_>) -> String {
    element.text().collect::<String>().trim().to_string()
}

fn has_class(element: ElementRef<'_>, name: &str) -> bool {
    element.value().classes().any(|class| class == name)
}

/// Only the known display route and numeric pagination parameters are readable.
pub(super) fn readable_home(base: &Url, url: &Url) -> bool {
    if url.origin() != base.origin()
        || url.path() != "/home"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let mut keys = Vec::new();
    url.query_pairs().all(|(key, value)| {
        let valid = matches!(key.as_ref(), "page" | "per-page")
            && !keys.contains(&key.to_string())
            && value.parse::<u32>().is_ok_and(|n| (1..=1000).contains(&n));
        keys.push(key.to_string());
        valid
    })
}

/// Parse server-rendered tables without executing scripts or action links.
/// Source: https://docs.rs/scraper/0.24.0/scraper/
pub(super) fn parse_page(
    html: &str,
    page_url: &Url,
    expected_username: &str,
) -> Result<SessionPage, QueryError> {
    let document = Html::parse_document(html);
    if document
        .select(&selector("input[name='LoginForm[password]']"))
        .next()
        .is_some()
    {
        return Err(QueryError::Authentication);
    }
    let authenticated = document.select(&selector("form")).any(|form| {
        form.value()
            .attr("method")
            .is_some_and(|method| method.eq_ignore_ascii_case("post"))
            && form
                .value()
                .attr("action")
                .and_then(|action| page_url.join(action).ok())
                .is_some_and(|url| {
                    url.origin() == page_url.origin() && url.path() == "/site/logout"
                })
    });
    if !authenticated {
        return Err(QueryError::Parse);
    }

    let mut online_table = None;
    for table in document.select(&selector("table")) {
        let headers: Vec<_> = table
            .select(&selector("th"))
            .map(|header| {
                text(header)
                    .split_whitespace()
                    .collect::<String>()
                    .to_lowercase()
            })
            .collect();
        let account = headers
            .iter()
            .position(|h| h == "用户名" || h == "username");
        let ip = headers
            .iter()
            .position(|h| h == "ip地址" || h == "ipaddress");
        let login_time = headers.iter().any(|h| h == "上线时间" || h == "logintime");
        if let (Some(account), Some(ip), true) = (account, ip, login_time) {
            if online_table.is_some() {
                return Err(QueryError::Parse);
            }
            online_table = Some((table, account, ip, headers.len()));
        }
    }
    let (table, account_column, ip_column, column_count) = online_table.ok_or(QueryError::Parse)?;
    let mut ips = Vec::new();
    let mut explicit_empty = false;
    for row in table.select(&selector("tr")) {
        let cells: Vec<_> = row
            .children()
            .filter_map(ElementRef::wrap)
            .filter(|cell| cell.value().name() == "td")
            .collect();
        if cells.is_empty() {
            continue;
        }
        if cells.len() == 1
            && cells[0]
                .value()
                .attr("colspan")
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|span| span >= column_count)
            && (has_class(cells[0], "empty")
                || cells[0].select(&selector(".empty")).next().is_some())
        {
            explicit_empty = true;
            continue;
        }
        let username = text(*cells.get(account_column).ok_or(QueryError::Parse)?);
        let expected = expected_username.trim();
        let same_account = username == expected
            || (!username.is_empty()
                && !username.contains('@')
                && expected
                    .strip_prefix(&username)
                    .is_some_and(|suffix| suffix.starts_with('@') && suffix.len() > 1));
        if !same_account {
            return Err(QueryError::AccountMismatch);
        }
        let ip = text(*cells.get(ip_column).ok_or(QueryError::Parse)?)
            .parse::<IpAddr>()
            .map_err(|_| QueryError::Parse)?;
        ips.push(ip);
    }
    if ips.is_empty() && !explicit_empty {
        return Err(QueryError::Parse);
    }
    if !ips.is_empty() && explicit_empty {
        return Err(QueryError::Parse);
    }

    let grid = table
        .ancestors()
        .filter_map(ElementRef::wrap)
        .find(|element| has_class(*element, "grid-view"));
    let pagination = selector(".pagination a");
    let container = grid.unwrap_or_else(|| document.root_element());
    let mut pages = Vec::new();
    for link in container.select(&pagination) {
        if link
            .ancestors()
            .filter_map(ElementRef::wrap)
            .any(|element| has_class(element, "disabled") || has_class(element, "active"))
        {
            continue;
        }
        let href = link.value().attr("href").ok_or(QueryError::Pagination)?;
        let url = page_url.join(href).map_err(|_| QueryError::Pagination)?;
        if !readable_home(page_url, &url) {
            return Err(QueryError::Pagination);
        }
        pages.push(url);
    }
    Ok(SessionPage { ips, pages })
}
