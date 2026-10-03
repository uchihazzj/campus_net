use crate::core::xencode::param_i;
use md5::Md5;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn decode_body(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    // UTF-8 failed, try GBK (common for Chinese campus network servers)
    if let Some(s) = encoding_rs::Encoding::for_label("gbk".as_bytes()).and_then(|enc| {
        let (cow, _enc, had_errors) = enc.decode(bytes);
        if had_errors {
            None
        } else {
            Some(cow.into_owned())
        }
    }) {
        return s;
    }
    // Last resort: lossy UTF-8
    String::from_utf8_lossy(bytes).into_owned()
}

const PATH_GET_CHALLENGE: &str = "/cgi-bin/get_challenge";
const PATH_PORTAL: &str = "/cgi-bin/srun_portal";

fn hmac_md5(key: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hash = Md5::digest(key);
        key_block[..16].copy_from_slice(&hash[..]);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner = Md5::digest(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 16);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner[..]);
    let outer = Md5::digest(&outer_input);
    format!("{:x}", outer)
}

#[derive(Default, Debug, Clone)]
pub struct SrunClient {
    pub auth_server: String,
    pub username: String,
    pub password: String,
    pub ip: String,
    pub client_ip: String,
    pub detect_ip: bool,
    pub strict_bind: bool,
    pub retry_delay: u32,
    pub retry_times: u32,
    pub test_before_login: bool,
    pub acid: i32,
    pub double_stack: i32,
    pub os: String,
    pub name: String,
    pub token: String,
    pub n: i32,
    pub utype: i32,
    pub time: u64,
}

fn unix_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_http_client(strict_bind: bool, ip: &str) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .no_proxy();

    if strict_bind && !ip.is_empty() {
        let local_addr: std::net::IpAddr = ip
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid bind IP '{}': {}", ip, e))?;
        builder = builder.local_address(local_addr);
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
    query: &[(&str, &str)],
) -> anyhow::Result<T> {
    let resp = client
        .get(url)
        .query(query)
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;

    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("Authentication server returned HTTP {}", status.as_u16());
    }

    let bytes = resp.bytes().await.map_err(reqwest::Error::without_url)?;
    let body = decode_body(&bytes);
    let json_str = crate::core::jsonp::strip_jsonp(&body)
        .map_err(|_| anyhow::anyhow!("Authentication server returned invalid JSONP"))?;

    parse_json_response(json_str)
}

fn parse_json_response<T: for<'de> Deserialize<'de>>(json_str: &str) -> anyhow::Result<T> {
    serde_json::from_str(json_str).map_err(|e| {
        anyhow::anyhow!(
            "Authentication response JSON error at line {}, column {} ({:?})",
            e.line(),
            e.column(),
            e.classify()
        )
    })
}

fn validate_logout_response(result: &PortalResponse) -> anyhow::Result<()> {
    if result.error == "not_online"
        || result.error == "ok"
        || (result.error.is_empty() && (result.res == "ok" || result.suc_msg == "logout_ok"))
    {
        return Ok(());
    }
    anyhow::bail!(
        "Logout rejected: error={}, error_msg={}, res={}",
        result.error,
        result.error_msg,
        result.res
    )
}

fn validate_challenge(token: &str) -> anyhow::Result<()> {
    // The existing encoder indexes four u32 key words. Short replies are
    // protocol failures, not usable challenges; never pass them to x_encode.
    if token.len() < 13 {
        anyhow::bail!("get_challenge returned an empty or truncated challenge");
    }
    Ok(())
}

impl SrunClient {
    pub fn new_for_logout(auth_server: &str, username: &str, ip: &str, acid: i32) -> Self {
        Self {
            auth_server: Self::normalize_server_url(auth_server),
            username: username.to_owned(),
            password: String::new(),
            ip: ip.to_owned(),
            client_ip: ip.to_owned(),
            acid,
            ..Default::default()
        }
    }

    pub fn new(auth_server: &str, username: &str, password: &str, ip: &str) -> Self {
        Self {
            auth_server: Self::normalize_server_url(auth_server),
            username: username.to_owned(),
            password: password.to_owned(),
            ip: ip.to_owned(),
            client_ip: ip.to_owned(),
            acid: 8,
            n: 200,
            utype: 1,
            os: "Windows 10".to_string(),
            name: "Windows".to_string(),
            retry_delay: 1000,
            retry_times: 3,
            ..Default::default()
        }
    }

    pub fn set_detect_ip(mut self, b: bool) -> Self {
        self.detect_ip = b;
        self
    }

    pub fn set_strict_bind(mut self, b: bool) -> Self {
        self.strict_bind = b;
        self
    }

    pub fn set_double_stack(mut self, b: bool) -> Self {
        self.double_stack = b as i32;
        self
    }

    pub fn set_n(mut self, n: i32) -> Self {
        self.n = n;
        self
    }

    pub fn set_type(mut self, t: i32) -> Self {
        self.utype = t;
        self
    }

    pub fn set_acid(mut self, acid: i32) -> Self {
        self.acid = acid;
        self
    }

    pub fn set_os(mut self, os: &str) -> Self {
        self.os = os.to_string();
        self
    }

    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn set_retry_delay(mut self, d: u32) -> Self {
        self.retry_delay = d;
        self
    }

    pub fn set_retry_times(mut self, t: u32) -> Self {
        self.retry_times = t;
        self
    }

    pub fn set_test_before_login(mut self, b: bool) -> Self {
        self.test_before_login = b;
        self
    }

    pub fn normalize_server_url(url: &str) -> String {
        let url = url.trim();
        if url.is_empty() {
            return String::new();
        }
        let with_scheme = if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{}", url)
        } else {
            url.to_string()
        };
        if let Some(pos) = with_scheme
            .get(8..)
            .and_then(|s| s.find('/'))
            .map(|p| p + 8)
        {
            with_scheme[..pos].to_string()
        } else {
            with_scheme
        }
    }

    pub async fn detect_ip(&mut self) -> anyhow::Result<()> {
        self.time = unix_second().saturating_sub(2);
        let client = build_http_client(self.strict_bind, &self.ip)?;

        // Validate server URL
        if !self.auth_server.starts_with("http://") && !self.auth_server.starts_with("https://") {
            anyhow::bail!(
                "Invalid server URL: '{}'. Must start with http:// or https://",
                self.auth_server
            );
        }

        let url = format!("{}{}", self.auth_server, PATH_GET_CHALLENGE);
        let time_str = self.time.to_string();
        let query = [
            ("callback", "sdu"),
            ("username", &self.username),
            ("ip", &self.client_ip),
            ("_", &time_str),
        ];
        let challenge: ChallengeResponse = fetch_json(&client, &url, &query).await?;
        let detected_ip = if !challenge.online_ip.is_empty() {
            Some(challenge.online_ip)
        } else if !challenge.client_ip.is_empty() {
            Some(challenge.client_ip)
        } else {
            None
        };
        if let Some(ip) = detected_ip {
            self.client_ip = ip;
            return Ok(());
        }

        // Fallback: enumerate local private addresses (10.x, 172.16-31.x, 192.168.x)
        let ifaces = crate::core::utils::get_network_interfaces();
        for (_, ip) in &ifaces {
            if ip.is_ipv4() {
                let s = ip.to_string();
                if s.starts_with("10.")
                    || (s.starts_with("172.") && {
                        let second: u32 =
                            s[4..].split('.').next().unwrap_or("0").parse().unwrap_or(0);
                        (16..=31).contains(&second)
                    })
                    || s.starts_with("192.168.")
                {
                    self.client_ip = s;
                    return Ok(());
                }
            }
        }

        // No private IP found — list all available IPs in error
        let all_ips: Vec<String> = ifaces.iter().map(|(_, ip)| ip.to_string()).collect();
        anyhow::bail!(
            "Cannot detect campus IP. Available local IPs: [{}]. Please configure IP manually or set if_name.",
            all_ips.join(", ")
        )
    }

    pub async fn get_token(&mut self) -> anyhow::Result<String> {
        if self.client_ip.is_empty() {
            anyhow::bail!(
                "IP is empty — server didn't return online_ip and no local private IP found. \
                 Please configure a static IP for this user in settings."
            );
        }
        self.time = unix_second().saturating_sub(2);
        let client = build_http_client(self.strict_bind, &self.ip)?;
        let url = format!("{}{}", self.auth_server, PATH_GET_CHALLENGE);
        let time_str = self.time.to_string();
        let query = [
            ("callback", "sdu"),
            ("username", &self.username),
            ("ip", &self.client_ip),
            ("_", &time_str),
        ];
        let challenge: ChallengeResponse = fetch_json(&client, &url, &query).await?;
        match challenge.challenge {
            Some(token) => {
                validate_challenge(&token)?;
                self.token = token;
                Ok(self.token.clone())
            }
            None => {
                let mut reason = String::new();
                if !challenge.error_msg.is_empty() {
                    reason.push_str(&format!("error_msg={}", challenge.error_msg));
                }
                if !challenge.res.is_empty() && challenge.res != "ok" {
                    if !reason.is_empty() {
                        reason.push_str(", ");
                    }
                    reason.push_str(&format!("res={}", challenge.res));
                }
                if reason.is_empty() {
                    reason = "no token".to_string();
                }
                anyhow::bail!("get_challenge failed: {}", reason)
            }
        }
    }

    pub async fn login(&mut self) -> anyhow::Result<()> {
        if self.test_before_login {
            if let Ok(delay) = crate::core::utils::tcp_ping("baidu.com:80").await {
                tracing::info!("Network already connected, ping={}ms", delay);
                return Ok(());
            }
        }

        if self.detect_ip {
            self.detect_ip().await?;
        }
        self.get_token().await?;

        if self.client_ip.is_empty() {
            anyhow::bail!("IP undefined after get_token");
        }

        let hmd5 = hmac_md5(self.token.as_bytes(), self.password.as_bytes());

        let param_i = param_i(
            &self.username,
            &self.password,
            &self.client_ip,
            self.acid,
            &self.token,
        );

        let check_sum = {
            let data = [
                "",
                &self.username,
                &hmd5,
                &self.acid.to_string(),
                &self.client_ip,
                &self.n.to_string(),
                &self.utype.to_string(),
                &param_i,
            ]
            .join(&self.token);
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(data.as_bytes());
            format!("{:x}", sha1_hasher.finalize())
        };

        let password_header = format!("{{MD5}}{}", hmd5);
        let ac_id = self.acid.to_string();
        let n_str = self.n.to_string();
        let type_str = self.utype.to_string();
        let double_stack_str = self.double_stack.to_string();
        let time_str = self.time.to_string();

        let mut last_error = String::new();
        let retries = if self.retry_times == 0 {
            1
        } else {
            self.retry_times
        };
        for ti in 1..=retries {
            let client = match build_http_client(self.strict_bind, &self.ip) {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("Failed to build HTTP client: {}", e);
                    tracing::warn!("Login attempt {}/{}: {}", ti, retries, msg);
                    last_error = msg;
                    if ti < retries {
                        tokio::time::sleep(Duration::from_millis(self.retry_delay as u64)).await;
                    }
                    continue;
                }
            };
            let url = format!("{}{}", self.auth_server, PATH_PORTAL);
            let query = [
                ("callback", "sdu"),
                ("action", "login"),
                ("username", &self.username),
                ("password", &password_header),
                ("ip", &self.client_ip),
                ("ac_id", &ac_id),
                ("n", &n_str),
                ("type", &type_str),
                ("os", &self.os),
                ("name", &self.name),
                ("double_stack", &double_stack_str),
                ("info", &param_i),
                ("chksum", &check_sum),
                ("_", &time_str),
            ];

            match fetch_json::<PortalResponse>(&client, &url, &query).await {
                Ok(result) => {
                    if !result.access_token.is_empty() {
                        tracing::info!(
                            "Login success: attempt {}/{} access_token=<redacted>",
                            ti,
                            retries
                        );
                        return Ok(());
                    }
                    let mut parts: Vec<String> = Vec::new();
                    if !result.error.is_empty() {
                        parts.push(format!("error={}", result.error));
                    }
                    if !result.error_msg.is_empty() {
                        parts.push(format!("error_msg={}", result.error_msg));
                    }
                    if !result.res.is_empty() && result.res != "ok" {
                        parts.push(format!("res={}", result.res));
                    }
                    let msg = if parts.is_empty() {
                        "portal returned no access_token".to_string()
                    } else {
                        parts.join(", ")
                    };
                    tracing::warn!("Login attempt {}/{}: {}", ti, retries, msg);
                    last_error = msg;
                }
                Err(e) => {
                    let msg = e.to_string();
                    tracing::warn!(
                        "Login attempt {}/{} failed (network/parse): {}",
                        ti,
                        retries,
                        msg
                    );
                    last_error = msg;
                }
            }

            if ti < retries {
                tokio::time::sleep(Duration::from_millis(self.retry_delay as u64)).await;
            }
        }

        anyhow::bail!(last_error);
    }

    pub async fn logout(&mut self) -> anyhow::Result<()> {
        if self.detect_ip {
            self.detect_ip().await?;
        }
        let client = build_http_client(self.strict_bind, &self.ip)?;
        let url = format!("{}{}", self.auth_server, PATH_PORTAL);
        let ac_id = self.acid.to_string();
        let time_str = unix_second().to_string();

        let query = [
            ("callback", "sdu"),
            ("action", "logout"),
            ("username", &self.username),
            ("ip", &self.client_ip),
            ("ac_id", &ac_id),
            ("_", &time_str),
        ];

        let result: PortalResponse = fetch_json(&client, &url, &query).await?;
        validate_logout_response(&result)?;
        tracing::info!(
            "Logout: username={}, suc_msg={}, error_msg={}",
            self.username,
            result.suc_msg,
            result.error_msg
        );
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct ChallengeResponse {
    challenge: Option<String>,
    #[serde(default)]
    client_ip: String,
    #[serde(default)]
    online_ip: String,
    #[serde(default)]
    error_msg: String,
    #[serde(default)]
    res: String,
    #[serde(default)]
    srun_ver: String,
    #[serde(default)]
    st: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[allow(dead_code)]
struct PortalResponse {
    #[serde(rename = "ServerFlag")]
    server_flag: i32,
    #[serde(rename = "ServicesIntfServerIP")]
    services_intf_server_ip: String,
    #[serde(rename = "ServicesIntfServerPort")]
    services_intf_server_port: String,
    access_token: String,
    checkout_date: u64,
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_msg: String,
    client_ip: String,
    online_ip: String,
    real_name: String,
    remain_flux: i64,
    remain_times: i32,
    res: String,
    srun_ver: String,
    suc_msg: String,
    sysver: String,
    username: String,
    wallet_balance: i32,
    st: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_empty_and_short_challenges() {
        for token in ["", "a", "123456789012"] {
            assert!(validate_challenge(token).is_err());
        }
        assert!(validate_challenge("1234567890123").is_ok());
        assert!(validate_challenge("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn logout_rejects_explicit_failure_and_missing_result() {
        for json in [r#"{}"#, r#"{"error":"logout_error","error_msg":"failed"}"#] {
            let response: PortalResponse = serde_json::from_str(json).unwrap();
            assert!(validate_logout_response(&response).is_err());
        }
    }

    #[test]
    fn logout_accepts_success_and_already_offline() {
        for json in [
            r#"{"error":"ok","suc_msg":"logout_ok","res":"ok"}"#,
            r#"{"res":"ok","suc_msg":"logout_ok"}"#,
            r#"{"error":"not_online","error_msg":"already offline"}"#,
        ] {
            let response: PortalResponse = serde_json::from_str(json).unwrap();
            assert!(validate_logout_response(&response).is_ok());
        }
    }

    #[test]
    fn malformed_response_does_not_expose_token_payload() {
        let error = parse_json_response::<PortalResponse>(
            r#"{"access_token":"test-sensitive-sentinel", broken}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("test-sensitive-sentinel"));
    }

    #[test]
    fn response_decoder_handles_utf8_and_gbk() {
        let body = "sdu({\"error_msg\":\"认证失败\"})";
        assert_eq!(decode_body(body.as_bytes()), body);
        let (encoded, _, errors) = encoding_rs::GBK.encode(body);
        assert!(!errors);
        assert_eq!(decode_body(&encoded), body);
    }
}
