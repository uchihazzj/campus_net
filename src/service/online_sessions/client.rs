use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use base64::Engine;
use md5::{Digest, Md5};
use reqwest::{Client, StatusCode, Url};

use super::parser::{parse_page, readable_home};
use super::QueryError;
use crate::service::config::StoredUser;

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAGES: usize = 20;

// Deliberately no Debug: neither responses nor clients are diagnostic output.
pub(super) struct HttpPage {
    pub status: StatusCode,
    pub location: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

pub(super) trait Transport {
    fn get(&self, url: Url) -> impl Future<Output = Result<HttpPage, QueryError>> + Send;
}

pub(super) struct WebSession {
    pub client: Client,
    pub authenticated: bool,
}

impl WebSession {
    pub fn new(source: Ipv4Addr) -> Result<Self, QueryError> {
        // One client/store per account. No file-backed cookies, proxy or redirects.
        // https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html#method.cookie_store
        let client = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .local_address(IpAddr::V4(source))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| QueryError::Network)?;
        Ok(Self {
            client,
            authenticated: false,
        })
    }
}

pub(super) async fn request(client: &Client, url: Url) -> Result<HttpPage, QueryError> {
    // Do not propagate reqwest errors: their URLs can contain SSO credentials.
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| QueryError::Network)?;
    let status = response.status();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // Redirect bodies are irrelevant; never follow or interpret their links.
    if status.is_redirection() {
        return Ok(HttpPage {
            status,
            location,
            content_type,
            body: Vec::new(),
        });
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_BODY_BYTES as u64)
    {
        return Err(QueryError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| QueryError::Network)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(QueryError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpPage {
        status,
        location,
        content_type,
        body,
    })
}

fn is_login_redirect(base: &Url, response: &HttpPage) -> bool {
    response
        .location
        .as_deref()
        .and_then(|value| base.join(value).ok())
        .is_some_and(|url| url.origin() == base.origin() && matches!(url.path(), "/login" | "/"))
}

async fn read_home<T: Transport>(
    transport: &T,
    base: &Url,
    username: &str,
) -> Result<Vec<IpAddr>, QueryError> {
    let mut pages = vec![base.join("/home").map_err(|_| QueryError::NotConfigured)?];
    let mut visited = Vec::new();
    let mut ips = Vec::new();
    while let Some(url) = pages.pop() {
        if visited.contains(&url) {
            continue;
        }
        if visited.len() >= MAX_PAGES || !readable_home(base, &url) {
            return Err(QueryError::Pagination);
        }
        visited.push(url.clone());
        let response = transport.get(url.clone()).await?;
        if response.status.is_redirection() {
            return Err(if is_login_redirect(base, &response) {
                QueryError::Authentication
            } else {
                QueryError::Redirect
            });
        }
        if matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(QueryError::Authentication);
        }
        if response.status != StatusCode::OK {
            return Err(QueryError::Network);
        }
        if response.body.len() > MAX_BODY_BYTES {
            return Err(QueryError::TooLarge);
        }
        let html = crate::core::srun::decode_body(&response.body, response.content_type.as_deref())
            .map_err(|_| QueryError::Parse)?;
        let page = parse_page(&html, &url, username)?;
        ips.extend(page.ips);
        if ips.len() > 4096 {
            return Err(QueryError::TooLarge);
        }
        pages.extend(page.pages);
    }
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

pub(super) async fn load<T: Transport>(
    transport: &T,
    base: &Url,
    user: &StoredUser,
    authenticated: &mut bool,
) -> Result<Vec<IpAddr>, QueryError> {
    if *authenticated {
        let result = read_home(transport, base, &user.username).await;
        if result != Err(QueryError::Authentication) {
            return result;
        }
        *authenticated = false;
    }
    let username = user.username.trim();
    let password = crate::platform::secure_store::decrypt_password(&user.encrypted_password)
        .map_err(|_| QueryError::Credentials)?;
    if username.is_empty() || password.is_empty() {
        return Err(QueryError::Credentials);
    }
    let digest = format!("{:x}", Md5::digest(password.as_bytes()));
    // Official .55 main.js password branch; never use username:username.
    let data =
        base64::engine::general_purpose::STANDARD.encode(format!("zh-CN:{username}:{digest}"));
    let mut url = base
        .join("/site/sso")
        .map_err(|_| QueryError::NotConfigured)?;
    url.query_pairs_mut().append_pair("data", &data);
    let response = transport.get(url).await?;
    let destination = response
        .location
        .as_deref()
        .and_then(|value| base.join(value).ok());
    if !matches!(
        response.status,
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER
    ) || !destination.is_some_and(|url| readable_home(base, &url) && url.query().is_none())
    {
        return Err(QueryError::Authentication);
    }
    *authenticated = true;
    let result = read_home(transport, base, username).await;
    if result == Err(QueryError::Authentication) {
        *authenticated = false;
    }
    result
}
