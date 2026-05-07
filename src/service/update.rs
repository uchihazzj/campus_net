use serde::Deserialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::service::SharedState;

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Idle,
    Checking,
    UpToDate,
    Available {
        latest: String,
        release_url: String,
        download_url: String,
    },
    Downloading,
    PreparingUpdate,
    Restarting,
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

/// Compare two version strings like "0.2.1" and "v0.3.0".
/// Strips a leading 'v', splits by '.', compares each component as u32.
/// Returns true if `remote` > `local`.
fn is_newer(local: &str, remote: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.trim_start_matches('v')
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let a = parse(local);
    let b = parse(remote);
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match bv.cmp(&av) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// Check GitHub Releases for a newer version.
/// Returns Some(UpdateInfo) if an update is available,
/// None if up to date, or Err(message) if the check failed.
pub async fn check_update() -> Result<Option<(String, String, String)>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .no_proxy()
        .user_agent("campus-net-client")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get("https://api.github.com/repos/uchihazzj/campus_net/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }

    let release: GitHubRelease = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let local = env!("CARGO_PKG_VERSION");

    if !is_newer(local, &release.tag_name) {
        return Ok(None);
    }

    let download_url = release
        .assets
        .iter()
        .find(|a| a.name == "campus-net-client.exe")
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| "No campus-net-client.exe asset found in release".to_string())?;

    Ok(Some((release.tag_name, release.html_url, download_url)))
}

fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Failed to get exe path: {}", e))?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "Failed to get exe directory".to_string())
}

fn app_log(msg: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("app.log")
    {
        let _ = writeln!(file, "{}", msg);
    }
}

/// Download the latest exe from GitHub, generate updater script, launch it, and exit.
pub async fn perform_update(state: SharedState, version: String, download_url: String) {
    let clean_ver = version.trim_start_matches('v');
    let download_filename = format!("campus-net-client-v{}.exe", clean_ver);

    // ── Step 1: Download ────────────────────────────────
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Downloading;
        s.add_log(format!("[INFO] Downloading {} ...", download_filename));
    }
    crate::service::request_ui_repaint();

    let dir = match exe_dir() {
        Ok(d) => d,
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(e.clone());
            s.add_log(format!("[ERROR] {}", e));
            app_log(&format!("[ERROR] {}", e));
            crate::service::request_ui_repaint();
            return;
        }
    };

    let download_path = dir.join(format!("{}.download", download_filename));
    let final_path = dir.join(&download_filename);

    // Download the asset
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .no_proxy()
        .user_agent("campus-net-client")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to build HTTP client: {}", e);
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(msg.clone());
            s.add_log(format!("[ERROR] {}", msg));
            app_log(&format!("[ERROR] {}", msg));
            crate::service::request_ui_repaint();
            return;
        }
    };

    let bytes = match client.get(&download_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                let msg = format!("Download failed: HTTP {}", resp.status().as_u16());
                let mut s = state.lock().unwrap();
                s.update_status = UpdateStatus::Failed(msg.clone());
                s.add_log(format!("[ERROR] {}", msg));
                app_log(&format!("[ERROR] {}", msg));
                crate::service::request_ui_repaint();
                return;
            }
            match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("Download failed: {}", e);
                    let mut s = state.lock().unwrap();
                    s.update_status = UpdateStatus::Failed(msg.clone());
                    s.add_log(format!("[ERROR] {}", msg));
                    app_log(&format!("[ERROR] {}", msg));
                    crate::service::request_ui_repaint();
                    return;
                }
            }
        }
        Err(e) => {
            let msg = format!("Download failed: {}", e);
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(msg.clone());
            s.add_log(format!("[ERROR] {}", msg));
            app_log(&format!("[ERROR] {}", msg));
            crate::service::request_ui_repaint();
            return;
        }
    };

    // Write to .download temp file
    if let Err(e) = std::fs::write(&download_path, &bytes) {
        let msg = format!("Failed to write download: {}", e);
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Failed(msg.clone());
        s.add_log(format!("[ERROR] {}", msg));
        app_log(&format!("[ERROR] {}", msg));
        crate::service::request_ui_repaint();
        return;
    }

    // Rename .download → final name
    if let Err(e) = std::fs::rename(&download_path, &final_path) {
        let msg = format!("Failed to rename download: {}", e);
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Failed(msg.clone());
        s.add_log(format!("[ERROR] {}", msg));
        app_log(&format!("[ERROR] {}", msg));
        crate::service::request_ui_repaint();
        let _ = std::fs::remove_file(&download_path);
        return;
    }

    // ── Step 2: Generate updater script ──────────────────
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::PreparingUpdate;
        s.add_log("[INFO] Generating updater script...".to_string());
    }
    crate::service::request_ui_repaint();

    let old_exe = dir.join("campus-net-client.exe");
    let bak_exe = dir.join("campus-net-client.exe.bak");

    let script = r#"param(
    [string]$OldExe,
    [string]$NewExe,
    [string]$BakExe
)

$ErrorActionPreference = "Stop"

Start-Sleep -Seconds 2
$timeout = 30
while ($timeout -gt 0) {
    $proc = Get-Process -Name "campus-net-client" -ErrorAction SilentlyContinue
    if (-not $proc) { break }
    Start-Sleep -Seconds 1
    $timeout--
}

try {
    if (Test-Path -LiteralPath $OldExe) {
        Move-Item -LiteralPath $OldExe -Destination $BakExe -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $NewExe -Destination $OldExe -Force -ErrorAction Stop
    Start-Process -FilePath $OldExe
    Start-Sleep -Seconds 3
    if (Test-Path -LiteralPath $BakExe) {
        Remove-Item -LiteralPath $BakExe -Force
    }
} catch {
    if ((Test-Path -LiteralPath $BakExe) -and (-not (Test-Path -LiteralPath $OldExe))) {
        Move-Item -LiteralPath $BakExe -Destination $OldExe -Force -ErrorAction SilentlyContinue
    }
}

# Self-cleanup
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"#
    .to_string();

    let script_path = dir.join("updater.ps1");
    if let Err(e) = std::fs::write(&script_path, script.as_bytes()) {
        let msg = format!("Failed to write updater script: {}", e);
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Failed(msg.clone());
        s.add_log(format!("[ERROR] {}", msg));
        app_log(&format!("[ERROR] {}", msg));
        crate::service::request_ui_repaint();
        return;
    }

    // ── Step 3: Save config and launch updater ────────────
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Restarting;
        s.add_log("[INFO] Launching updater and exiting...".to_string());
    }
    crate::service::request_ui_repaint();

    // Save config before exit
    {
        let s = state.lock().unwrap();
        let _ = crate::service::config::write_config("config.json", &s.config);
    }

    let old_exe_str = old_exe.to_string_lossy().to_string();
    let final_path_str = final_path.to_string_lossy().to_string();
    let bak_exe_str = bak_exe.to_string_lossy().to_string();
    let script_path_str = script_path.to_string_lossy().to_string();

    match std::process::Command::new("powershell.exe")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
            &script_path_str,
            "-OldExe",
            &old_exe_str,
            "-NewExe",
            &final_path_str,
            "-BakExe",
            &bak_exe_str,
        ])
        .spawn()
    {
        Ok(_) => {
            app_log("[INFO] Updater launched, exiting...");
            crate::app::FORCE_QUIT.store(true, Ordering::SeqCst);
            std::process::exit(0);
        }
        Err(e) => {
            let msg = format!("Failed to launch updater: {}", e);
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(msg.clone());
            s.add_log(format!("[ERROR] {}", msg));
            app_log(&format!("[ERROR] {}", msg));
            crate::service::request_ui_repaint();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.2.1", "v0.3.0"));
        assert!(is_newer("0.2.1", "v0.2.2"));
        assert!(!is_newer("0.2.1", "v0.2.1"));
        assert!(!is_newer("0.3.0", "v0.2.1"));
        assert!(!is_newer("0.2.1", "v0.2.0"));
        assert!(is_newer("0.2.1", "v1.0.0"));
        assert!(is_newer("1.0.0", "v1.0.1"));
        assert!(!is_newer("1.0.0", "v1.0.0"));
        assert!(!is_newer("0.2.1", "0.2.1"));
    }
}
