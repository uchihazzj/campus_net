use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use reqwest::{StatusCode, Url};

use super::{online_sessions, SharedState, Ticket};
use crate::service::online_info::{match_account, MatchResult, OnlineUserInfo};
use crate::service::online_sessions::QueryError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Gateway,
    InternetBound204,
    InternetBoundText,
    InternetDefaultText,
}

impl Target {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Gateway => "gateway_bound",
            Self::InternetBound204 => "internet_bound_204",
            Self::InternetBoundText => "internet_bound_msft",
            Self::InternetDefaultText => "internet_default_msft",
        }
    }
}

pub(super) struct Check {
    pub verdict: &'static str,
    pub code: &'static str,
    // Only locally constructed numeric/enum/bool details. Never raw I/O text.
    pub details: String,
}

impl Check {
    pub fn fail(code: &'static str) -> Self {
        Self {
            verdict: "FAIL",
            code,
            details: String::new(),
        }
    }

    pub fn skip(code: &'static str) -> Self {
        Self {
            verdict: "SKIP",
            code,
            details: String::new(),
        }
    }

    pub fn sessions(ips: &[IpAddr], source: Option<Ipv4Addr>) -> Self {
        Self {
            verdict: "PASS",
            code: "list_parsed",
            details: format!(
                " count={} source_present={} ipv6_count={}",
                ips.len(),
                source.is_some_and(|ip| ips.contains(&IpAddr::V4(ip))),
                ips.iter().filter(|ip| ip.is_ipv6()).count(),
            ),
        }
    }

    pub fn session_error(error: QueryError) -> Self {
        Self {
            verdict: if error == QueryError::NotConfigured {
                "SKIP"
            } else {
                "FAIL"
            },
            code: "self_service_error",
            details: format!(" category={error:?}"),
        }
    }
}

pub(super) trait Backend: Sync {
    fn probe(&self, target: Target) -> impl Future<Output = Check> + Send;
    fn sessions(
        &self,
        index: usize,
    ) -> impl Future<Output = Result<Vec<IpAddr>, QueryError>> + Send;
}

pub(super) struct Network<'a> {
    pub state: &'a SharedState,
    pub ticket: &'a Ticket,
}

impl Backend for Network<'_> {
    async fn probe(&self, target: Target) -> Check {
        if !self.ticket.current(self.state) {
            return Check::fail("context_changed");
        }
        let url = match target {
            Target::Gateway => match gateway_url(&self.ticket.config.server) {
                Some(url) => url,
                None => return Check::fail("invalid_gateway"),
            },
            // Reuse the two endpoints already used by detection.rs. Never
            // navigate a browser or follow the response's redirects/links.
            Target::InternetBound204 => {
                Url::parse("http://connect.rom.miui.com/generate_204").unwrap()
            }
            Target::InternetBoundText | Target::InternetDefaultText => {
                Url::parse("http://www.msftconnecttest.com/connecttest.txt").unwrap()
            }
        };
        let source = if target == Target::InternetDefaultText {
            None
        } else {
            self.ticket.source
        };
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(7));
        if let Some(source) = source {
            builder = builder.local_address(IpAddr::V4(source));
        }
        let client = match builder.build() {
            Ok(client) => client,
            Err(_) => return Check::fail("client_build"),
        };
        let response = match fetch(&client, url).await {
            Ok(response) => response,
            Err(code) => return Check::fail(code),
        };
        classify(target, &response, self.ticket)
    }

    async fn sessions(&self, index: usize) -> Result<Vec<IpAddr>, QueryError> {
        let source = self.ticket.source.ok_or(QueryError::Network)?;
        let user = self
            .ticket
            .config
            .users
            .get(index)
            .ok_or(QueryError::Interrupted)?;
        online_sessions::diagnostic_query(&self.ticket.config, source, user, || {
            self.ticket.current(self.state)
        })
        .await
    }
}

fn gateway_url(server: &str) -> Option<Url> {
    // Validate before normalization; the legacy Srun helper would turn e.g.
    // file:///... into an HTTP host, hiding the unsupported scheme.
    let server = server.trim();
    let normalized = if server.contains("://") {
        server.to_owned()
    } else {
        format!("http://{server}")
    };
    let base = Url::parse(&normalized).ok()?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return None;
    }
    let mut url = base.join("/cgi-bin/rad_user_info").ok()?;
    url.query_pairs_mut()
        .append_pair("callback", "sdu")
        .append_pair("_", &chrono::Utc::now().timestamp_millis().to_string());
    Some(url)
}

// No Debug/Display: these values may contain personal data and server messages.
struct Response {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
}

async fn fetch(client: &reqwest::Client, url: Url) -> Result<Response, &'static str> {
    const MAX_BYTES: usize = 256 * 1024;
    let mut response = client.get(url).send().await.map_err(network_error)?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // A redirect is a result, never permission to access another endpoint.
    let mut body = Vec::new();
    if status == StatusCode::OK {
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BYTES as u64)
        {
            return Err("body_too_large");
        }
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if body.len() + chunk.len() > MAX_BYTES {
                return Err("body_too_large");
            }
            body.extend_from_slice(&chunk);
        }
    }
    Ok(Response {
        status,
        content_type,
        body,
    })
}

fn network_error(error: reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect_failed"
    } else {
        "request_failed"
    }
}

fn classify(target: Target, response: &Response, ticket: &Ticket) -> Check {
    if target != Target::Gateway {
        let expected = match target {
            Target::InternetBound204 => response.status == StatusCode::NO_CONTENT,
            _ => response.status == StatusCode::OK && response.body == b"Microsoft Connect Test",
        };
        return Check {
            verdict: if expected { "PASS" } else { "WARN" },
            code: if expected {
                "expected_response"
            } else if response.status.is_redirection() {
                "redirect_possible_portal"
            } else {
                "unexpected_response"
            },
            details: format!(" http={}", response.status.as_u16()),
        };
    }
    if response.status != StatusCode::OK {
        return Check {
            verdict: "FAIL",
            code: "gateway_http",
            details: format!(" http={}", response.status.as_u16()),
        };
    }
    let encoding_details = encoding_details(response);
    let decoded =
        match crate::core::srun::decode_body(&response.body, response.content_type.as_deref()) {
            Ok(body) => body,
            Err(_) => {
                return Check {
                    verdict: "FAIL",
                    code: "decode_failed",
                    details: encoding_details,
                }
            }
        };
    let info = crate::core::jsonp::strip_jsonp(&decoded)
        .ok()
        .and_then(|body| serde_json::from_str::<OnlineUserInfo>(body).ok());
    let Some(info) = info else {
        return Check {
            verdict: "FAIL",
            code: "invalid_status_format",
            details: encoding_details,
        };
    };
    let mut check = match info.error.as_str() {
        "ok" if !info.user_name.trim().is_empty() => {
            let matched = match_account(&info.user_name, &ticket.config.users);
            let known_account =
                matches!(matched, MatchResult::Exact(_) | MatchResult::UniqueBase(_));
            let account = match matched {
                MatchResult::Exact(index) | MatchResult::UniqueBase(index) => {
                    format!("A{}", index + 1)
                }
                MatchResult::Ambiguous(_) => "ambiguous".into(),
                MatchResult::NoMatch => "unconfigured".into(),
            };
            let source_matches = info
                .online_ip
                .parse::<Ipv4Addr>()
                .ok()
                .zip(ticket.source)
                .is_some_and(|(a, b)| a == b);
            Check {
                verdict: if known_account && source_matches {
                    "PASS"
                } else {
                    "WARN"
                },
                code: "authenticated",
                details: format!(" account={} source_matches={}", account, source_matches),
            }
        }
        "not_online" | "not_online_error" => Check {
            verdict: "WARN",
            code: "not_authenticated",
            details: String::new(),
        },
        _ => Check::fail("unknown_auth_status"),
    };
    check.details.push_str(&encoding_details);
    check
}

fn encoding_details(response: &Response) -> String {
    let declared = response.content_type.as_deref().and_then(|content_type| {
        content_type.split(';').skip(1).find_map(|parameter| {
            let (name, label) = parameter.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| label.trim().trim_matches(['\'', '"']))
        })
    });
    // Finite categories only. Never copy a server-controlled header into logs.
    let declared = match declared {
        None => "absent",
        Some(label) => match encoding_rs::Encoding::for_label(label.as_bytes()) {
            Some(encoding) if encoding == encoding_rs::UTF_8 => "utf8",
            Some(encoding) if encoding == encoding_rs::GBK => "gbk",
            Some(encoding) if encoding == encoding_rs::GB18030 => "gb18030",
            Some(_) => "other_known",
            None => "unknown",
        },
    };
    let bom = match encoding_rs::Encoding::for_bom(&response.body).map(|(encoding, _)| encoding) {
        Some(encoding) if encoding == encoding_rs::UTF_8 => "utf8",
        Some(_) => "utf16",
        None => "absent",
    };
    format!(
        " http=200 raw_utf8_valid={} declared_charset={} bom={}",
        std::str::from_utf8(&response.body).is_ok(),
        declared,
        bom
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::diagnostics::tests::fixture;

    #[test]
    fn server_payloads_are_reduced_to_safe_categories() {
        let state = fixture();
        let ticket = crate::service::diagnostics::claim(&state).unwrap();
        let response = Response { status: StatusCode::OK, content_type: None,
            body: br#"sdu({"error":"ok","user_name":"fixture-account-SECRET","online_ip":"10.9.8.7","real_name":"PRIVATE-PERSON"})"#.to_vec() };
        let check = classify(Target::Gateway, &response, &ticket);
        assert_eq!(check.code, "authenticated");
        assert!(check.details.contains("account=A1 source_matches=true"));
        assert!(!check.details.contains("SECRET"));
        assert!(!check.details.contains("10.9.8.7"));
        for body in [
            br#"sdu({"error":"server-SECRET"})"#.as_slice(),
            b"<html>PRIVATE-PERSON</html>",
            &[0xff, 0xff],
        ] {
            let response = Response {
                status: StatusCode::OK,
                content_type: None,
                body: body.to_vec(),
            };
            let check = classify(Target::Gateway, &response, &ticket);
            assert_eq!(check.verdict, "FAIL");
            assert!(!format!("{}{}", check.code, check.details).contains("SECRET"));
        }
    }

    #[test]
    fn redirects_and_altered_connectivity_bodies_do_not_pass() {
        let state = fixture();
        let ticket = crate::service::diagnostics::claim(&state).unwrap();
        let mut response = Response {
            status: StatusCode::FOUND,
            content_type: None,
            body: Vec::new(),
        };
        assert_eq!(
            classify(Target::InternetBoundText, &response, &ticket).code,
            "redirect_possible_portal"
        );
        response.status = StatusCode::OK;
        response.body = b"Microsoft Connect Test<script>portal</script>".to_vec();
        assert_eq!(
            classify(Target::InternetBoundText, &response, &ticket).code,
            "unexpected_response"
        );
        response.body = b"Microsoft Connect Test".to_vec();
        assert_eq!(
            classify(Target::InternetDefaultText, &response, &ticket).verdict,
            "PASS"
        );
    }

    #[test]
    fn legacy_encoding_and_mismatched_source_are_visible_without_personal_data() {
        let state = fixture();
        let ticket = crate::service::diagnostics::claim(&state).unwrap();
        let body = r#"sdu({"error":"ok","user_name":"fixture-account-SECRET","online_ip":"10.9.8.9","products_name":"测试套餐"})"#;
        let (bytes, _, errors) = encoding_rs::GBK.encode(body);
        assert!(!errors);
        let response = Response {
            status: StatusCode::OK,
            content_type: Some("text/javascript; charset=gbk".into()),
            body: bytes.into_owned(),
        };
        let check = classify(Target::Gateway, &response, &ticket);
        assert_eq!(check.verdict, "WARN");
        assert!(check.details.contains("source_matches=false"));
        assert!(check
            .details
            .contains("raw_utf8_valid=false declared_charset=gbk"));
        assert!(!check.details.contains("SECRET"));
        assert!(!check.details.contains("测试套餐"));
    }

    #[test]
    fn valid_utf8_bytes_do_not_override_a_declared_gbk_label_in_the_report() {
        let state = fixture();
        let ticket = crate::service::diagnostics::claim(&state).unwrap();
        let body = r#"sdu({"error":"not_online","products_name":"忙"})"#;
        let (bytes, _, errors) = encoding_rs::GBK.encode(body);
        assert!(!errors);
        assert!(std::str::from_utf8(&bytes).is_ok());
        let response = Response {
            status: StatusCode::OK,
            content_type: Some("text/javascript; charset=gbk".into()),
            body: bytes.into_owned(),
        };
        let check = classify(Target::Gateway, &response, &ticket);
        assert_eq!(check.code, "not_authenticated");
        assert!(check
            .details
            .contains("raw_utf8_valid=true declared_charset=gbk bom=absent"));
        assert!(!check.details.contains("encoding=utf8"));
        assert!(!check.details.contains("忙"));
    }

    #[test]
    fn gateway_has_only_the_read_only_status_path() {
        let url = gateway_url("http://10.0.0.55").unwrap();
        assert_eq!(url.path(), "/cgi-bin/rad_user_info");
        assert_eq!(url.query_pairs().next().unwrap().1, "sdu");
        for (index, server) in [
            "",
            "http://user:password@example.test",
            "http://example.test?data=SECRET",
            "file:///tmp",
        ]
        .iter()
        .enumerate()
        {
            assert!(gateway_url(server).is_none(), "invalid fixture {index}");
        }
    }
}
