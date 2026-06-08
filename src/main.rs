#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod core;
mod path;
mod platform;
mod service;
mod ui;

use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use path::{config_path, ensure_data_dir, log_path, migrate_config};
use service::config::{read_config_with_report, ConfigLoadSource};
use service::SharedState;

/// Rotate log files: app.log → app.log.1 → app.log.2 → app.log.3 (deleted).
/// Keeps at most `keep` backups. Only rotates if `app.log` exceeds `max_bytes`.
fn rotate_log_if_needed(path: &Path, max_bytes: u64, keep: usize) {
    if !path.exists() {
        return;
    }
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("WARNING: Cannot stat {}: {}", path.display(), e);
            return;
        }
    };
    if size <= max_bytes {
        return;
    }
    // Remove oldest backup
    let oldest = path.with_extension(format!("log.{}", keep));
    if oldest.exists() {
        let _ = std::fs::remove_file(&oldest);
    }
    // Shift backups
    for i in (1..keep).rev() {
        let src = path.with_extension(format!("log.{}", i));
        let dst = path.with_extension(format!("log.{}", i + 1));
        if src.exists() {
            let _ = std::fs::rename(&src, &dst);
        }
    }
    // Rename current log to .1
    let first = path.with_extension("log.1");
    if let Err(e) = std::fs::rename(path, &first) {
        eprintln!(
            "WARNING: Failed to rotate {} → {}: {}",
            path.display(),
            first.display(),
            e
        );
    }
}

const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const LOG_KEEP: usize = 3;

/// Owned writer that holds an Arc<Mutex<File>>. Each call to write()
/// acquires the lock, writes, and releases.
struct FileWriterGuard {
    inner: Arc<Mutex<std::fs::File>>,
}

impl io::Write for FileWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.lock().unwrap().flush()
    }
}

/// Thread-safe MakeWriter for tracing layers. Clones the inner Arc on
/// each make_writer() call, returning an owned FileWriterGuard.
#[derive(Clone)]
struct FileWriter {
    inner: Arc<Mutex<std::fs::File>>,
}

impl FileWriter {
    fn new(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        let is_new = !p.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap_or_else(|e| {
                eprintln!(
                    "WARNING: Failed to open {} ({}), logging to NUL",
                    p.display(),
                    e
                );
                OpenOptions::new()
                    .write(true)
                    .open("NUL")
                    .expect("Failed to open NUL")
            });
        if is_new {
            use std::io::Write;
            let mut f = &file;
            let _ = f.write_all(b"\xEF\xBB\xBF");
        }
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }
}

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = FileWriterGuard;

    fn make_writer(&self) -> Self::Writer {
        FileWriterGuard {
            inner: self.inner.clone(),
        }
    }
}

fn load_cjk_font() -> Option<egui::FontData> {
    let font_paths = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyhbd.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "C:\\Windows\\Fonts\\Deng.ttf",
    ];
    for path in &font_paths {
        if let Ok(data) = std::fs::read(path) {
            tracing::info!("Loaded CJK font: {}", path);
            return Some(egui::FontData::from_owned(data));
        }
    }
    tracing::warn!("No CJK font found, Chinese text may not display");
    None
}

fn main() -> anyhow::Result<()> {
    // Install panic hook early — write panic info + backtrace to app.log
    let panic_log_path = log_path();
    // Track whether we're already inside the panic hook to prevent
    // double-panic if the hook itself panics (e.g. file I/O failure).
    // A double-panic aborts the process without any log output.
    static PANIC_HOOK_ACTIVE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    std::panic::set_hook(Box::new(move |info| {
        // Guard against double-panic — if the hook itself panics, abort
        // with a best-effort message to stderr.
        if PANIC_HOOK_ACTIVE.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                b"FATAL: double panic in panic hook, aborting\n",
            );
            return;
        }

        let backtrace = std::backtrace::Backtrace::capture();
        let msg = format!("=== PANIC ===\n{}\n\nBacktrace:\n{}\n", info, backtrace);
        let is_new = !panic_log_path.exists();
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&panic_log_path)
        {
            use std::io::Write;
            if is_new {
                let _ = file.write_all(b"\xEF\xBB\xBF");
            }
            let _ = writeln!(file, "{}", msg);
            // Must flush — without this, buffered data may not reach disk
            // before the process terminates (e.g. on abort after panic).
            let _ = file.flush();
        }
        eprintln!("{}", msg);
    }));

    // Ensure C:\ProgramData\CampusNetClient exists before any file I/O
    let data_dir_error = match ensure_data_dir() {
        Ok(()) => None,
        Err(e) => {
            eprintln!("FATAL: Failed to create app data directory: {}", e);
            Some(e)
        }
    };

    // Migrate old config to ProgramData if needed
    let migration_msg = match migrate_config() {
        Ok((true, msg)) => Some(msg),
        Ok((false, _)) => None,
        Err(e) => {
            let msg = format!("Config migration failed: {}", e);
            eprintln!("{}", msg);
            Some(msg)
        }
    };

    // Rotate log before opening, so FileWriter always starts fresh if rotated
    rotate_log_if_needed(&log_path(), LOG_MAX_BYTES, LOG_KEEP);

    let log_file = FileWriter::new(log_path());

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(io::stderr);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(log_file);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "campus_net_client=info".into()),
        )
        .with(stderr_layer)
        .with(file_layer)
        .init();

    tracing::info!("Starting Campus Net Client...");

    // ── Startup path diagnostics ──────────────────────────
    let _current_exe = std::env::current_exe();
    let _current_dir = std::env::current_dir();
    let cfg_path = config_path();
    let log_p = log_path();
    tracing::info!(
        "current_exe={:?}, current_dir={:?}, config_path={}, log_path={}",
        _current_exe
            .as_deref()
            .unwrap_or(&std::path::PathBuf::from("<unknown>"))
            .display(),
        _current_dir
            .as_deref()
            .unwrap_or(&std::path::PathBuf::from("<unknown>"))
            .display(),
        cfg_path.display(),
        log_p.display(),
    );
    if let Some(ref e) = data_dir_error {
        tracing::error!("app_data_dir creation failed: {}", e);
    }
    if let Some(ref msg) = migration_msg {
        tracing::info!("config_migration: {}", msg);
    }

    // ── Detect leftover update artifacts ────────────────────
    // Store a message for the UI log (AppState not yet created at this point).
    let mut startup_update_warning: Option<String> = None;

    if let Ok(exe_dir) = std::env::current_exe().and_then(|p| {
        p.parent()
            .map(|d| d.to_path_buf())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }) {
        // Check for updater log from previous failed update
        let updater_log = exe_dir.join("updater.log");
        if updater_log.exists() {
            match std::fs::read_to_string(&updater_log) {
                Ok(contents) => {
                    let last_lines: Vec<&str> = contents.lines().rev().take(5).collect();
                    let summary = last_lines
                        .iter()
                        .rev()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n");
                    tracing::warn!(
                        "Found updater.log from previous update attempt. Last lines:\n{}",
                        summary
                    );
                    startup_update_warning = Some(format!(
                        "[WARN] Last update may have failed. Updater log:\n{}",
                        summary
                    ));
                }
                Err(e) => {
                    tracing::warn!("Found unreadable updater.log: {}", e);
                }
            }
            let _ = std::fs::remove_file(&updater_log);
        }

        // Clean up leftover download artifacts
        for entry in std::fs::read_dir(&exe_dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".download") || name_str.ends_with(".exe.bak") {
                tracing::warn!("Cleaning up leftover update artifact: {}", name_str);
                startup_update_warning = Some(format!(
                    "[WARN] Found leftover update artifact: {}",
                    name_str
                ));
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    // Build tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let _rt_guard = rt.enter();

    // Load config
    let (config, config_load_messages) = match read_config_with_report(config_path()) {
        Ok(report) => {
            for msg in &report.messages {
                match report.source {
                    ConfigLoadSource::Main | ConfigLoadSource::DefaultMissing => {
                        tracing::info!("{}", msg);
                    }
                    ConfigLoadSource::Backup | ConfigLoadSource::DefaultAfterFailure => {
                        tracing::warn!("{}", msg);
                    }
                }
            }
            (report.config, report.messages)
        }
        Err(e) => {
            let msg = format!(
                "[WARN] Failed to load config after recovery attempts, using defaults: {}",
                e
            );
            tracing::warn!("{}", msg);
            (service::config::AppConfig::default(), vec![msg])
        }
    };
    tracing::info!("Config loaded: {} users", config.users.len());

    // Read saved window size or use default
    let window_w = config.window_width.unwrap_or(520.0);
    let window_h = config.window_height.unwrap_or(350.0);

    let state: SharedState = Arc::new(Mutex::new(service::AppState::new(config)));

    // Surface any updater artifact warnings in the UI log
    if let Some(ref msg) = startup_update_warning {
        if let Ok(mut s) = state.lock() {
            s.add_log(msg.clone());
        }
    }
    if !config_load_messages.is_empty() {
        if let Ok(mut s) = state.lock() {
            for msg in config_load_messages {
                s.add_log(msg);
            }
        }
    }

    // Spawn update scheduler (startup check + retry + daily)
    service::update_scheduler::spawn_update_scheduler(state.clone());

    // Spawn startup tasks: online state sync → conditional auto-login → monitor
    service::online_info::spawn_startup_tasks(state.clone());

    // Build window icon
    let icon_data = app::create_window_icon();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([window_w, window_h])
            .with_title("Campus Net Client")
            .with_icon(icon_data),
        ..Default::default()
    };

    let app = app::CampusNetApp::new(state);

    eframe::run_native(
        "Campus Net Client",
        native_options,
        Box::new(move |cc| {
            if let Some(font_data) = load_cjk_font() {
                let mut fonts = egui::FontDefinitions::default();
                fonts.font_data.insert("cjk_font".to_owned(), font_data);
                fonts
                    .families
                    .get_mut(&egui::FontFamily::Proportional)
                    .unwrap()
                    .insert(0, "cjk_font".to_owned());
                fonts
                    .families
                    .get_mut(&egui::FontFamily::Monospace)
                    .unwrap()
                    .insert(0, "cjk_font".to_owned());
                cc.egui_ctx.set_fonts(fonts);
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {}", e))?;

    drop(_rt_guard);
    drop(rt);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_no_file() {
        let tmp = std::env::temp_dir().join("cnet_log_rotate_none.log");
        let _ = std::fs::remove_file(&tmp);
        rotate_log_if_needed(&tmp, 1024, 3);
        // Should not panic
        assert!(!tmp.exists());
    }

    #[test]
    fn rotate_small_file_not_rotated() {
        let tmp = std::env::temp_dir().join("cnet_log_rotate_small.log");
        let _ = std::fs::remove_file(&tmp);
        std::fs::write(&tmp, b"small").unwrap();
        rotate_log_if_needed(&tmp, 1024, 3);
        assert!(tmp.exists());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn rotate_large_file() {
        let tmp = std::env::temp_dir().join("cnet_log_rotate_big.log");
        let b1 = tmp.with_extension("log.1");
        let b2 = tmp.with_extension("log.2");
        let b3 = tmp.with_extension("log.3");
        for p in [&tmp, &b1, &b2, &b3] {
            let _ = std::fs::remove_file(p);
        }
        // Write > max_bytes
        let big = vec![b'x'; 2048];
        std::fs::write(&tmp, &big).unwrap();
        rotate_log_if_needed(&tmp, 1024, 3);
        // Original should be gone
        assert!(!tmp.exists());
        // Backup should exist with rotated content
        assert!(b1.exists());
        assert_eq!(std::fs::read_to_string(&b1).unwrap().len(), 2048);
        for p in [&b1, &b2, &b3] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn rotate_preserves_existing_backups() {
        let tmp = std::env::temp_dir().join("cnet_log_rotate_chain.log");
        let b1 = tmp.with_extension("log.1");
        let b2 = tmp.with_extension("log.2");
        let b3 = tmp.with_extension("log.3");
        for p in [&tmp, &b1, &b2, &b3] {
            let _ = std::fs::remove_file(p);
        }
        // Pre-create backups
        std::fs::write(&b1, b"backup1").unwrap();
        std::fs::write(&b2, b"backup2").unwrap();
        // Write large current log
        let big = vec![b'y'; 2048];
        std::fs::write(&tmp, &big).unwrap();
        rotate_log_if_needed(&tmp, 1024, 3);
        // b1 should now have old current content, b2 → old b1, b3 → old b2
        assert!(b1.exists());
        assert_eq!(std::fs::read_to_string(&b1).unwrap().len(), 2048);
        assert!(b2.exists());
        assert_eq!(
            std::fs::read_to_string(&b2).unwrap(),
            String::from_utf8_lossy(b"backup1")
        );
        assert!(b3.exists());
        assert_eq!(
            std::fs::read_to_string(&b3).unwrap(),
            String::from_utf8_lossy(b"backup2")
        );
        for p in [&tmp, &b1, &b2, &b3] {
            let _ = std::fs::remove_file(p);
        }
    }
}
