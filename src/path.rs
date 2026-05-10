use std::path::PathBuf;

pub fn app_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| {
            eprintln!(
                "WARNING: current_exe() failed, falling back to current_dir() for config/log paths"
            );
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        })
}

pub fn config_path() -> PathBuf {
    app_dir().join("config.json")
}

pub fn log_path() -> PathBuf {
    app_dir().join("app.log")
}
