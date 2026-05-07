use serde::{Deserialize, Serialize};

use crate::platform::secure_store;
use crate::ui::l10n::Lang;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub username: String,
    pub encrypted_password: String,
    pub ip: Option<String>,
    pub if_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: String,
    pub detect_ip: bool,
    pub strict_bind: bool,
    pub double_stack: bool,
    pub n: i32,
    #[serde(alias = "type")]
    pub utype: i32,
    pub acid: i32,
    pub os: String,
    pub name: String,
    pub retry_delay: u32,
    pub retry_times: u32,
    pub monitor_interval_secs: u64,
    pub auto_reconnect: bool,
    pub minimize_to_tray: bool,
    pub auto_start: bool,
    pub language: Lang,
    pub window_width: Option<f32>,
    pub window_height: Option<f32>,
    pub users: Vec<StoredUser>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: "http://10.0.0.55".to_string(),
            detect_ip: false,
            strict_bind: false,
            double_stack: false,
            n: 200,
            utype: 1,
            acid: 8,
            os: "Windows 10".to_string(),
            name: "Windows".to_string(),
            retry_delay: 1000,
            retry_times: 3,
            monitor_interval_secs: 30,
            auto_reconnect: true,
            minimize_to_tray: true,
            auto_start: true,
            language: Lang::Chinese,
            window_width: None,
            window_height: None,
            users: vec![],
        }
    }
}

impl AppConfig {
    #[allow(dead_code)]
    pub fn get_password(&self, user: &StoredUser) -> anyhow::Result<String> {
        secure_store::decrypt_password(&user.encrypted_password)
    }

    #[allow(dead_code)]
    pub fn set_password(&mut self, user_idx: usize, password: &str) -> anyhow::Result<()> {
        let encrypted = secure_store::encrypt_password(password)?;
        if let Some(u) = self.users.get_mut(user_idx) {
            u.encrypted_password = encrypted;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn resolve_ip(&self, user: &StoredUser) -> Option<String> {
        if let Some(ref ip) = user.ip {
            if !ip.is_empty() {
                return Some(ip.clone());
            }
        }
        if let Some(ref if_name) = user.if_name {
            if let Some(ip) = crate::core::utils::get_ip_by_if_name(if_name) {
                return Some(ip);
            }
        }
        None
    }
}

pub fn read_config(path: &str) -> anyhow::Result<AppConfig> {
    let mut config = match std::fs::read_to_string(path) {
        Ok(content) => {
            let c: AppConfig = serde_json::from_str(&content)?;
            c
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("Config file not found, using defaults");
            AppConfig::default()
        }
        Err(e) => anyhow::bail!("Failed to read config: {}", e),
    };

    // Fill in defaults for empty required fields
    let mut updated = false;
    if config.server.is_empty() {
        config.server = AppConfig::default().server;
        updated = true;
    }

    if updated {
        write_config(path, &config)?;
    }

    Ok(config)
}

pub fn write_config(path: &str, config: &AppConfig) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}
