use std::path::{Path, PathBuf};

/// Returns the machine-level application data directory.
pub fn app_data_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\CampusNetClient")
}

/// Returns the config file path: C:\ProgramData\CampusNetClient\config.json
pub fn config_path() -> PathBuf {
    app_data_dir().join("config.json")
}

/// Returns the log file path: C:\ProgramData\CampusNetClient\app.log
pub fn log_path() -> PathBuf {
    app_data_dir().join("app.log")
}

/// Returns the directory containing the current executable, if available.
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
}

/// Create the app data directory and any missing parent directories.
pub fn ensure_data_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(app_data_dir())
}

/// Migrate config from old locations to C:\ProgramData\CampusNetClient\config.json.
///
/// Only migrates if the new path does NOT already exist.
/// Search order: exe directory, then current working directory.
///
/// Returns `(migrated, description)` on success, or an I/O error on failure.
pub fn migrate_config() -> std::io::Result<(bool, String)> {
    let new_path = config_path();

    if new_path.exists() {
        return Ok((false, String::new()));
    }

    let old_candidates = collect_old_config_candidates();
    try_migrate_config(&new_path, &old_candidates)
}

/// Collect candidate old config paths with labels, deduplicating identical paths.
fn collect_old_config_candidates() -> Vec<(PathBuf, &'static str)> {
    let mut candidates: Vec<(PathBuf, &'static str)> = Vec::new();

    if let Some(d) = exe_dir() {
        candidates.push((d.join("config.json"), "exe directory"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        let cwd_config = cwd.join("config.json");
        let is_dup = candidates.iter().any(|(p, _)| *p == cwd_config);
        if !is_dup {
            candidates.push((cwd_config, "current directory"));
        }
    }

    candidates
}

/// Core migration logic — copy the first existing old candidate to `new_path`.
/// If `new_path` already exists, migration is skipped.
/// Exposed as a free function so tests can supply controlled paths.
fn try_migrate_config(
    new_path: &Path,
    candidates: &[(PathBuf, &str)],
) -> std::io::Result<(bool, String)> {
    if new_path.exists() {
        return Ok((false, String::new()));
    }

    for (old_path, label) in candidates {
        if old_path.exists() {
            std::fs::copy(old_path, new_path)?;
            return Ok((
                true,
                format!(
                    "Migrated config from {} ({}) to {}",
                    old_path.display(),
                    label,
                    new_path.display()
                ),
            ));
        }
    }

    Ok((false, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_ends_with_programdata() {
        let p = config_path();
        assert!(
            p.to_str()
                .unwrap()
                .ends_with(r"CampusNetClient\config.json"),
            "unexpected config_path: {}",
            p.display()
        );
    }

    #[test]
    fn log_path_ends_with_programdata() {
        let p = log_path();
        assert!(
            p.to_str().unwrap().ends_with(r"CampusNetClient\app.log"),
            "unexpected log_path: {}",
            p.display()
        );
    }

    #[test]
    fn migrate_skips_when_new_exists() {
        let tmp = std::env::temp_dir().join("cnet_test_skip");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let new_path = tmp.join("config.json");
        std::fs::write(&new_path, r#"{"server":"","users":[]}"#).unwrap();

        let old_dir = tmp.join("old");
        std::fs::create_dir_all(&old_dir).unwrap();
        let old_path = old_dir.join("config.json");
        std::fs::write(&old_path, "old-content").unwrap();

        let candidates = vec![(old_path.clone(), "test-old")];
        let result = try_migrate_config(&new_path, &candidates).unwrap();

        // Should NOT migrate because new already exists
        assert!(!result.0);
        // New content should be unchanged
        let content = std::fs::read_to_string(&new_path).unwrap();
        assert!(content.contains(r#""server":"""#));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn migrate_copies_when_new_absent() {
        let tmp = std::env::temp_dir().join("cnet_test_copy");
        let _ = std::fs::remove_dir_all(&tmp);

        let old_dir = tmp.join("exe");
        std::fs::create_dir_all(&old_dir).unwrap();
        let old_path = old_dir.join("config.json");
        std::fs::write(&old_path, r#"{"server":"http://10.0.0.55","users":[]}"#).unwrap();

        let new_dir = tmp.join("ProgramData");
        std::fs::create_dir_all(&new_dir).unwrap();
        let new_path = new_dir.join("config.json");

        let candidates = vec![(old_path.clone(), "exe directory")];
        let result = try_migrate_config(&new_path, &candidates).unwrap();

        assert!(result.0, "expected migration to happen");
        assert!(result.1.contains("Migrated config"));
        assert!(new_path.exists());

        let content = std::fs::read_to_string(&new_path).unwrap();
        assert!(content.contains("10.0.0.55"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn migrate_no_candidates_available() {
        let tmp = std::env::temp_dir().join("cnet_test_none");
        let _ = std::fs::remove_dir_all(&tmp);

        let new_dir = tmp.join("ProgramData");
        std::fs::create_dir_all(&new_dir).unwrap();
        let new_path = new_dir.join("config.json");

        let nonexistent = tmp.join("no_such_config.json");
        let candidates = vec![(nonexistent, "nowhere")];
        let result = try_migrate_config(&new_path, &candidates).unwrap();

        assert!(!result.0, "migration should not happen with no candidates");
        assert!(!new_path.exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_config_returns_error_on_invalid_path() {
        let cfg = crate::service::config::AppConfig::default();
        let result = crate::service::config::write_config(r"Z:\impossible\path\config.json", &cfg);
        assert!(result.is_err());
    }
}
