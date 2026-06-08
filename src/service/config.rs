use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub enable_ipv4_internet_probe: bool,
    pub language: Lang,
    pub window_width: Option<f32>,
    pub window_height: Option<f32>,
    pub users: Vec<StoredUser>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLoadSource {
    Main,
    Backup,
    DefaultMissing,
    DefaultAfterFailure,
}

#[derive(Debug, Clone)]
pub struct ConfigLoadReport {
    pub config: AppConfig,
    pub source: ConfigLoadSource,
    pub messages: Vec<String>,
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
            enable_ipv4_internet_probe: false,
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

enum ConfigReadFailure {
    NotFound,
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl std::fmt::Display for ConfigReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "file not found"),
            Self::Io(e) => write!(f, "failed to read config: {}", e),
            Self::Parse(e) => write!(f, "failed to parse config JSON: {}", e),
        }
    }
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.json");
    path.with_file_name(format!("{}.{}", name, suffix))
}

fn config_tmp_path(path: &Path) -> PathBuf {
    sibling_path(path, "tmp")
}

fn config_backup_path(path: &Path) -> PathBuf {
    sibling_path(path, "bak")
}

fn config_backup_tmp_path(path: &Path) -> PathBuf {
    sibling_path(path, "bak.tmp")
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn damaged_config_backup_path(path: &Path) -> PathBuf {
    sibling_path(path, &format!("bad-{}", unix_timestamp_secs()))
}

fn parse_config_file(path: &Path) -> Result<AppConfig, ConfigReadFailure> {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).map_err(ConfigReadFailure::Parse),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ConfigReadFailure::NotFound),
        Err(e) => Err(ConfigReadFailure::Io(e)),
    }
}

fn fill_required_defaults(config: &mut AppConfig) -> bool {
    let mut updated = false;
    if config.server.is_empty() {
        config.server = AppConfig::default().server;
        updated = true;
    }
    updated
}

fn backup_damaged_config(path: &Path, messages: &mut Vec<String>) {
    if !path.exists() {
        return;
    }

    let bad_path = damaged_config_backup_path(path);
    match std::fs::copy(path, &bad_path) {
        Ok(_) => messages.push(format!(
            "[WARN] Backed up damaged config to {}",
            bad_path.display()
        )),
        Err(e) => messages.push(format!(
            "[WARN] Failed to back up damaged config {}: {}",
            path.display(),
            e
        )),
    }
}

fn atomic_write_config(path: &Path, content: &str, keep_backup: bool) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = config_tmp_path(path);
    let backup_path = config_backup_path(path);
    let backup_tmp_path = config_backup_tmp_path(path);

    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }

    if keep_backup && path.exists() && parse_config_file(path).is_ok() {
        if backup_tmp_path.exists() {
            let _ = std::fs::remove_file(&backup_tmp_path);
        }
        std::fs::copy(path, &backup_tmp_path)?;
        {
            let backup_file = OpenOptions::new().write(true).open(&backup_tmp_path)?;
            backup_file.sync_all()?;
        }
        std::fs::rename(&backup_tmp_path, &backup_path)?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn read_config_with_report(path: impl AsRef<Path>) -> anyhow::Result<ConfigLoadReport> {
    let path = path.as_ref();
    let mut messages = Vec::new();

    match parse_config_file(path) {
        Ok(mut config) => {
            if fill_required_defaults(&mut config) {
                write_config(path, &config)?;
                messages.push("[INFO] Filled missing config defaults".to_string());
            }
            return Ok(ConfigLoadReport {
                config,
                source: ConfigLoadSource::Main,
                messages,
            });
        }
        Err(ConfigReadFailure::NotFound) => {
            tracing::info!("Config file not found, using defaults");
            messages.push("[INFO] Config file not found, using defaults".to_string());
            return Ok(ConfigLoadReport {
                config: AppConfig::default(),
                source: ConfigLoadSource::DefaultMissing,
                messages,
            });
        }
        Err(e) => {
            messages.push(format!(
                "[WARN] Failed to load config {}: {}",
                path.display(),
                e
            ));
            backup_damaged_config(path, &mut messages);
        }
    }

    let backup_path = config_backup_path(path);
    match parse_config_file(&backup_path) {
        Ok(mut config) => {
            fill_required_defaults(&mut config);
            let content = serde_json::to_string_pretty(&config)?;
            match atomic_write_config(path, &content, false) {
                Ok(()) => messages.push(format!(
                    "[WARN] Restored config from backup {}",
                    backup_path.display()
                )),
                Err(e) => messages.push(format!(
                    "[WARN] Loaded backup config but failed to restore {}: {}",
                    path.display(),
                    e
                )),
            }
            Ok(ConfigLoadReport {
                config,
                source: ConfigLoadSource::Backup,
                messages,
            })
        }
        Err(e) => {
            messages.push(format!(
                "[WARN] Backup config {} is unavailable: {}",
                backup_path.display(),
                e
            ));
            messages.push(
                "[WARN] Using default config after main and backup config failed".to_string(),
            );
            Ok(ConfigLoadReport {
                config: AppConfig::default(),
                source: ConfigLoadSource::DefaultAfterFailure,
                messages,
            })
        }
    }
}

#[allow(dead_code)]
pub fn read_config(path: impl AsRef<Path>) -> anyhow::Result<AppConfig> {
    Ok(read_config_with_report(path)?.config)
}

pub fn write_config(path: impl AsRef<Path>, config: &AppConfig) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    atomic_write_config(path.as_ref(), &content, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cnet_config_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_config_creates_backup_and_removes_temp() {
        let dir = temp_dir("atomic_write");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"server":"old","users":[]}"#).unwrap();

        let mut cfg = AppConfig::default();
        cfg.server = "http://10.0.0.55".to_string();
        write_config(&path, &cfg).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("10.0.0.55"));

        let backup = std::fs::read_to_string(dir.join("config.json.bak")).unwrap();
        assert!(backup.contains(r#""server":"old""#));
        assert!(!dir.join("config.json.tmp").exists());
        assert!(!dir.join("config.json.bak.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_config_recovers_from_backup_when_main_is_corrupt() {
        let dir = temp_dir("recover_backup");
        let path = dir.join("config.json");
        std::fs::write(&path, "{bad json").unwrap();
        std::fs::write(
            &dir.join("config.json.bak"),
            r#"{"server":"http://backup","users":[]}"#,
        )
        .unwrap();

        let report = read_config_with_report(&path).unwrap();

        assert_eq!(report.source, ConfigLoadSource::Backup);
        assert_eq!(report.config.server, "http://backup");
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("http://backup"));
        assert!(std::fs::read_dir(&dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("config.json.bad-")
        }));
        assert!(report
            .messages
            .iter()
            .any(|msg| msg.contains("Restored config from backup")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_config_uses_defaults_when_main_and_backup_fail() {
        let dir = temp_dir("default_after_failure");
        let path = dir.join("config.json");
        std::fs::write(&path, "{bad json").unwrap();
        std::fs::write(&dir.join("config.json.bak"), "{also bad").unwrap();

        let report = read_config_with_report(&path).unwrap();

        assert_eq!(report.source, ConfigLoadSource::DefaultAfterFailure);
        assert_eq!(report.config.server, AppConfig::default().server);
        assert!(report
            .messages
            .iter()
            .any(|msg| msg.contains("Using default config")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_does_not_replace_backup_when_main_is_corrupt() {
        let dir = temp_dir("preserve_backup");
        let path = dir.join("config.json");
        let backup_path = dir.join("config.json.bak");
        std::fs::write(&path, "{bad json").unwrap();
        std::fs::write(
            &backup_path,
            r#"{"server":"http://safe-backup","users":[]}"#,
        )
        .unwrap();

        let mut cfg = AppConfig::default();
        cfg.server = "http://new-default".to_string();
        write_config(&path, &cfg).unwrap();

        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("http://new-default"));
        assert!(std::fs::read_to_string(&backup_path)
            .unwrap()
            .contains("http://safe-backup"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
