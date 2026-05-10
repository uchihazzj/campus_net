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

use path::{config_path, log_path};
use service::config::read_config;
use service::SharedState;

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
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::capture();
        let msg = format!("=== PANIC ===\n{}\n\nBacktrace:\n{}\n", info, backtrace);
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&panic_log_path)
        {
            use std::io::Write;
            let _ = writeln!(file, "{}", msg);
        }
        eprintln!("{}", msg);
    }));

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

    // Build tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let _rt_guard = rt.enter();

    // Load config
    let config = match read_config(config_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to load config, using defaults: {}", e);
            service::config::AppConfig::default()
        }
    };
    tracing::info!("Config loaded: {} users", config.users.len());

    // Read saved window size or use default
    let window_w = config.window_width.unwrap_or(520.0);
    let window_h = config.window_height.unwrap_or(350.0);

    let state: SharedState = Arc::new(Mutex::new(service::AppState::new(config)));

    // Spawn startup tasks: version check → online state sync → monitor
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
