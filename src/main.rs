#![windows_subsystem = "windows"]

mod app;
mod core;
mod platform;
mod service;
mod ui;

use std::sync::{Arc, Mutex};

use service::config::read_config;
use service::SharedState;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "campus_net_client=info".into()),
        )
        .with_target(false)
        .init();

    tracing::info!("Starting Campus Net Client...");

    // Build tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let _rt_guard = rt.enter();

    // Load config
    let config = match read_config("config.json") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to load config, using defaults: {}", e);
            service::config::AppConfig::default()
        }
    };

    // Read saved window size or use default
    let window_w = config.window_width.unwrap_or(520.0);
    let window_h = config.window_height.unwrap_or(350.0);

    let state: SharedState = Arc::new(Mutex::new(service::AppState::new(config)));

    // Spawn network monitor
    service::monitor::spawn_monitor(state.clone());

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
            // Load CJK font for Chinese text support
            if let Some(font_data) = load_cjk_font() {
                let mut fonts = egui::FontDefinitions::default();
                fonts
                    .font_data
                    .insert("cjk_font".to_owned(), font_data);
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
    ).map_err(|e| anyhow::anyhow!("eframe error: {}", e))?;

    drop(_rt_guard);
    drop(rt);

    Ok(())
}
