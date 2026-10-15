use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ui::l10n::Lang;

static CONFIG_IO_LOCK: Mutex<()> = Mutex::new(());
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

fn config_backup_path(path: &Path) -> PathBuf {
    sibling_path(path, "bak")
}

/// Each save owns its files even when another client process is saving too.
struct ConfigTempFile(PathBuf);

impl Drop for ConfigTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn create_config_temp(path: &Path, suffix: &str) -> std::io::Result<(ConfigTempFile, File)> {
    loop {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tmp = sibling_path(
            path,
            &format!("{}-{}-{}", suffix, std::process::id(), sequence),
        );
        match OpenOptions::new().create_new(true).write(true).open(&tmp) {
            Ok(file) => return Ok((ConfigTempFile(tmp), file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
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
        Ok(content) => parse_config_text(&content).map_err(ConfigReadFailure::Parse),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ConfigReadFailure::NotFound),
        Err(e) => Err(ConfigReadFailure::Io(e)),
    }
}

fn parse_config_text(content: &str) -> Result<AppConfig, serde_json::Error> {
    serde_json::from_str(content.strip_prefix('\u{feff}').unwrap_or(content))
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
    let _guard = CONFIG_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    atomic_write_config_unlocked(path, content, keep_backup)
}

fn atomic_write_config_unlocked(
    path: &Path,
    content: &str,
    keep_backup: bool,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let backup_path = config_backup_path(path);
    let (tmp, mut file) = create_config_temp(path, "tmp")?;
    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);

    if keep_backup {
        if let Ok(previous) = std::fs::read_to_string(path) {
            if parse_config_text(&previous).is_ok() {
                let (backup_tmp, mut backup_file) = create_config_temp(path, "bak.tmp")?;
                backup_file.write_all(previous.as_bytes())?;
                backup_file.sync_all()?;
                drop(backup_file);
                std::fs::rename(&backup_tmp.0, &backup_path)?;
            }
        }
    }

    std::fs::rename(&tmp.0, path)?;
    Ok(())
}

pub fn read_config_with_report(path: impl AsRef<Path>) -> anyhow::Result<ConfigLoadReport> {
    let path = path.as_ref();
    let mut messages = Vec::new();

    match parse_config_file(path) {
        Ok(mut config) => {
            if fill_required_defaults(&mut config) {
                match write_config(path, &config) {
                    Ok(()) => messages.push("[INFO] Filled missing config defaults".to_string()),
                    Err(e) => messages.push(format!(
                        "[WARN] Failed to save filled config defaults: {}",
                        e
                    )),
                }
            }
            return Ok(ConfigLoadReport {
                config,
                source: ConfigLoadSource::Main,
                messages,
            });
        }
        Err(ConfigReadFailure::NotFound) => {
            if config_backup_path(path).exists() {
                messages.push("[WARN] Main config is missing; trying its backup".to_string());
            } else {
                tracing::info!("Config file not found, using defaults");
                messages.push("[INFO] Config file not found, using defaults".to_string());
                return Ok(ConfigLoadReport {
                    config: AppConfig::default(),
                    source: ConfigLoadSource::DefaultMissing,
                    messages,
                });
            }
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

pub fn write_config(path: impl AsRef<Path>, config: &AppConfig) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    atomic_write_config(path.as_ref(), &content, true)
}

/// Serialize saves and take the snapshot only when this write owns the file,
/// so a queued UI save cannot overwrite a newer quit/update save.
pub fn save_shared_config(
    path: impl AsRef<Path>,
    state: &crate::service::SharedState,
) -> anyhow::Result<()> {
    let _guard = CONFIG_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = state.lock().unwrap().config.clone();
    let content = serde_json::to_string_pretty(&config)?;
    atomic_write_config_unlocked(path.as_ref(), &content, true)
}

pub fn schedule_config_save(state: crate::service::SharedState) {
    {
        let mut s = state.lock().unwrap();
        if s.config_save_pending {
            return;
        }
        s.config_save_pending = true;
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let save_state = state.clone();
        let result = tokio::task::spawn_blocking(move || {
            save_state.lock().unwrap().config_save_pending = false;
            save_shared_config(crate::path::config_path(), &save_state)
        })
        .await;
        let error = match result {
            Ok(Ok(())) => return,
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };
        tracing::error!("Failed to save config: {}", error);
        let mut s = state.lock().unwrap();
        s.add_log(format!("[ERROR] Failed to save config: {}", error));
        drop(s);
        crate::service::request_ui_repaint();
    });
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
    fn saving_config_does_not_overwrite_another_writers_temporary_files() {
        let dir = temp_dir("foreign_temporary_files");
        let path = dir.join("config.json");
        let original = AppConfig::default();
        std::fs::write(&path, serde_json::to_string(&original).unwrap()).unwrap();
        let foreign_tmp = dir.join("config.json.tmp");
        let foreign_backup_tmp = dir.join("config.json.bak.tmp");
        std::fs::write(&foreign_tmp, "another writer's incomplete config").unwrap();
        std::fs::write(&foreign_backup_tmp, "another writer's incomplete backup").unwrap();

        let replacement = AppConfig {
            acid: 42,
            ..original.clone()
        };
        write_config(&path, &replacement).unwrap();

        assert_eq!(
            std::fs::read_to_string(&foreign_tmp).unwrap(),
            "another writer's incomplete config"
        );
        assert_eq!(
            std::fs::read_to_string(&foreign_backup_tmp).unwrap(),
            "another writer's incomplete backup"
        );
        assert_eq!(parse_config_file(&path).ok().unwrap().acid, 42);
        assert_eq!(
            parse_config_file(&config_backup_path(&path))
                .ok()
                .unwrap()
                .acid,
            original.acid
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn utf8_bom_config_keeps_its_accounts_and_settings() {
        let dir = temp_dir("utf8_bom");
        let path = dir.join("config.json");
        let config = AppConfig {
            acid: 42,
            users: vec![StoredUser {
                username: "test-bom-user".into(),
                encrypted_password: String::new(),
                ip: None,
                if_name: None,
            }],
            ..Default::default()
        };
        std::fs::write(
            &path,
            format!("\u{feff}{}", serde_json::to_string(&config).unwrap()),
        )
        .unwrap();
        let report = read_config_with_report(&path).unwrap();
        assert_eq!(report.source, ConfigLoadSource::Main);
        assert_eq!(report.config.acid, 42);
        assert_eq!(report.config.users, config.users);
        assert!(report.messages.is_empty());
        let replacement = AppConfig {
            acid: 43,
            ..config.clone()
        };
        write_config(&path, &replacement).unwrap();
        std::fs::remove_file(&path).unwrap();
        let recovered = read_config_with_report(&path).unwrap();
        assert_eq!(recovered.source, ConfigLoadSource::Backup);
        assert_eq!(recovered.config.acid, 42);
        assert_eq!(recovered.config.users, config.users);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_config_replacement_cleans_only_its_owned_temporary_files() {
        let dir = temp_dir("failed_replace_cleanup");
        let path = dir.join("config.json");
        std::fs::create_dir(&path).unwrap();
        let foreign = dir.join("other-process.tmp");
        std::fs::write(&foreign, "untouched").unwrap();
        assert!(write_config(&path, &AppConfig::default()).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        assert_eq!(std::fs::read_to_string(foreign).unwrap(), "untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn isolated_config_writer_process() {
        // Only the parent test supplies this path; the test harness never runs main().
        let Some(path) = std::env::var_os("CNET_TEST_MULTIWRITER_CONFIG_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let dir = path.parent().unwrap();
        assert!(dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("cnet_config_multiprocess_"));
        assert!(dir
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap()));
        let id: i32 = std::env::var("CNET_TEST_MULTIWRITER_ID")
            .unwrap()
            .parse()
            .unwrap();
        std::fs::write(dir.join(format!("ready-{}", id)), "ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !dir.join("start").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent did not start the isolated writers"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let config = AppConfig {
            acid: id,
            name: format!("test-writer-{}", id).repeat(4096),
            ..Default::default()
        };
        for _ in 0..40 {
            write_config(&path, &config).unwrap();
        }
    }

    #[test]
    fn simultaneous_processes_save_complete_configs_and_backups() {
        let dir = temp_dir("multiprocess");
        let path = dir.join("config.json");
        write_config(&path, &AppConfig::default()).unwrap();
        let test_exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for id in [41, 42] {
            let child = std::process::Command::new(&test_exe)
                .args([
                    "--exact",
                    "service::config::tests::isolated_config_writer_process",
                    "--test-threads=1",
                ])
                .env("CNET_TEST_MULTIWRITER_CONFIG_PATH", &path)
                .env("CNET_TEST_MULTIWRITER_ID", id.to_string())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            children.push(child);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !(dir.join("ready-41").exists() && dir.join("ready-42").exists()) {
            assert!(
                std::time::Instant::now() < deadline,
                "isolated writers did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::fs::write(dir.join("start"), "start").unwrap();
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "isolated writer failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for saved in [&path, &config_backup_path(&path)] {
            let config = parse_config_file(saved)
                .ok()
                .expect("saved JSON must be complete");
            assert!([41, 42].contains(&config.acid));
            assert_eq!(
                config.name,
                format!("test-writer-{}", config.acid).repeat(4096)
            );
        }
        assert!(!std::fs::read_dir(&dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_config_recovers_when_main_is_missing() {
        let dir = temp_dir("missing_main");
        let path = dir.join("config.json");
        std::fs::write(
            dir.join("config.json.bak"),
            r#"{"server":"http://backup","users":[]}"#,
        )
        .unwrap();
        let report = read_config_with_report(&path).unwrap();
        assert_eq!(report.source, ConfigLoadSource::Backup);
        assert_eq!(report.config.server, "http://backup");
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_valid_config_survives_default_save_failure() {
        let dir = temp_dir("defaults_save_failure");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"server":"","acid":42,"users":[]}"#).unwrap();
        std::fs::create_dir(dir.join("config.json.bak")).unwrap();
        let report = read_config_with_report(&path).unwrap();
        assert_eq!(report.config.acid, 42);
        assert_eq!(report.source, ConfigLoadSource::Main);
        assert!(report
            .messages
            .iter()
            .any(|msg| msg.contains("Failed to save")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_creates_backup_and_removes_temp() {
        let dir = temp_dir("atomic_write");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"server":"old","users":[]}"#).unwrap();

        let cfg = AppConfig::default();
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
            dir.join("config.json.bak"),
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
        std::fs::write(dir.join("config.json.bak"), "{also bad").unwrap();

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

        let cfg = AppConfig {
            server: "http://new-default".to_string(),
            ..AppConfig::default()
        };
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
