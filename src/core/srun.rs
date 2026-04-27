use crate::core::xencode::param_i;
use md5::Md5;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        .unwrap()
        .as_secs()
}

fn build_http_client(strict_bind: bool, ip: &str) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5));

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
    let resp = client.get(url).query(query).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("HTTP {}: {}", status.as_u16(), body);
    }

    let bytes = resp.bytes().await?;

    if bytes.len() < 5 {
        anyhow::bail!(
            "Server returned short response ({} bytes): {}",
            bytes.len(),
            String::from_utf8_lossy(&bytes)
        );
    }

    // srun wraps JSON as: sdu({...}) — strip 4-byte prefix and 1-byte suffix
    let inner = &bytes[4..bytes.len() - 1];
    serde_json::from_slice(inner)
        .map_err(|e| anyhow::anyhow!("JSON parse error: {}. Body: {}", e, String::from_utf8_lossy(inner)))
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
        if let Some(pos) = with_scheme.get(8..).and_then(|s| s.find('/')).map(|p| p + 8) {
            with_scheme[..pos].to_string()
        } else {
            with_scheme
        }
    }

    pub async fn detect_ip(&mut self) -> anyhow::Result<()> {
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
        let challenge: ChallengeResponse =
            fetch_json(&client, &url, &query).await?;
        if !challenge.online_ip.is_empty() {
            self.client_ip = challenge.online_ip;
        }
        Ok(())
    }

    pub async fn get_token(&mut self) -> anyhow::Result<String> {
        if self.client_ip.is_empty() {
            anyhow::bail!("IP undefined, cannot get challenge token");
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
        let challenge: ChallengeResponse =
            fetch_json(&client, &url, &query).await?;
        match challenge.challenge {
            Some(token) => {
                self.token = token;
                Ok(self.token.clone())
            }
            None => anyhow::bail!("get_challenge returned no token"),
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

        let mut result = PortalResponse::default();
        for ti in 1..=self.retry_times {
            let client = build_http_client(self.strict_bind, &self.ip)?;
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

            result = fetch_json(&client, &url, &query).await?;

            if !result.access_token.is_empty() {
                tracing::info!(
                    "Login success: attempt {}/{} access_token={}",
                    ti,
                    self.retry_times,
                    result.access_token
                );
                return Ok(());
            }

            tracing::warn!(
                "Login attempt {}/{} failed: {}",
                ti,
                self.retry_times,
                result.error_msg
            );
            tokio::time::sleep(Duration::from_millis(self.retry_delay as u64)).await;
        }

        let error_msg = if result.error_msg.is_empty() {
            "login failed after all retries".to_string()
        } else {
            result.error_msg.clone()
        };
        anyhow::bail!(error_msg);
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
