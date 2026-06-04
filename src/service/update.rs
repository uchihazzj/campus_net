use serde::Deserialize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::path::{config_path, log_path};
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

/// Proxy strategy order for GitHub requests. Used in tests to verify
/// the fallback order is correct without making real HTTP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum GithubCheckOrder {
    /// API check: direct first, fallback to system proxy
    DirectThenSystem,
    /// Download: system proxy first, fallback to direct
    SystemThenDirect,
}

/// API latest check order: direct first → system proxy fallback.
#[allow(dead_code)]
pub const API_CHECK_ORDER: GithubCheckOrder = GithubCheckOrder::DirectThenSystem;

/// Asset download order: system proxy first → direct fallback.
#[allow(dead_code)]
pub const DOWNLOAD_ORDER: GithubCheckOrder = GithubCheckOrder::SystemThenDirect;

fn user_agent() -> String {
    format!(
        "campus-net-client/{} (+https://github.com/uchihazzj/campus_net)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Build a reqwest `Client` for GitHub API or asset download.
///
/// `use_proxy = true` → lets reqwest use the system proxy (no `.no_proxy()`).
/// `use_proxy = false` → calls `.no_proxy()` for a direct connection.
fn build_github_client(use_proxy: bool, timeout_secs: u64) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(user_agent());
    if !use_proxy {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

/// Returns true when the HTTP status and response body indicate a GitHub
/// rate-limit response (403 with "rate limit" in body, or 429).
fn is_rate_limit_response(status: u16, body: &str) -> bool {
    status == 429 || (status == 403 && body.to_lowercase().contains("rate limit"))
}

fn format_rate_limit_error(
    status: u16,
    remaining: &str,
    reset: &str,
    request_id: &str,
    body: &str,
) -> String {
    format!(
        "GitHub API rate limit exceeded (HTTP {}). \
         Remaining: {}, Reset: {}, Request-ID: {}. Body: {}",
        status, remaining, reset, request_id, body
    )
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

async fn do_check_update(use_proxy: bool) -> Result<Option<(String, String, String)>, String> {
    let client = build_github_client(use_proxy, 8)?;

    let resp = client
        .get("https://api.github.com/repos/uchihazzj/campus_net/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        // Extract rate-limit headers before consuming the body
        let remaining = resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let reset = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let request_id = resp
            .headers()
            .get("x-github-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let body = resp.text().await.unwrap_or_default();
        let body_msg = crate::core::jsonp::safe_truncate(body.trim(), 300).to_string();

        if is_rate_limit_response(status.as_u16(), &body_msg) {
            return Err(format_rate_limit_error(
                status.as_u16(),
                &remaining,
                &reset,
                &request_id,
                &body_msg,
            ));
        }
        return Err(format!("HTTP {}: {}", status.as_u16(), body_msg));
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

/// Check GitHub Releases for a newer version.
///
/// Proxy strategy: **direct first** (`no_proxy`), then fall back to **system proxy**
/// if the direct request fails with a network error. If the system proxy request
/// also fails, the error is reported with rate-limit details when applicable.
///
/// Returns `Some((tag, release_url, download_url))` if an update is available,
/// `None` if up to date, or `Err(message)` if the check failed.
pub async fn check_update() -> Result<Option<(String, String, String)>, String> {
    // ── Try direct (no_proxy) first ──────────────────────
    match do_check_update(false).await {
        Ok(result) => return Ok(result),
        Err(direct_err) => {
            tracing::info!(
                "[Update] Direct API check failed: {} — falling back to system proxy",
                direct_err
            );
        }
    }

    // ── Fallback to system proxy ─────────────────────────
    do_check_update(true).await
}

/// Download an asset with system-proxy-first strategy.
/// Tries system proxy, then falls back to direct on failure.
async fn download_asset(url: &str) -> Result<Vec<u8>, String> {
    // ── Try system proxy first ──────────────────────────
    match do_download(url, true).await {
        Ok(bytes) => return Ok(bytes),
        Err(sys_err) => {
            tracing::info!(
                "[Update] System proxy download failed: {} — falling back to direct",
                sys_err
            );
        }
    }

    // ── Fallback to direct ─────────────────────────────
    match do_download(url, false).await {
        Ok(bytes) => Ok(bytes),
        Err(direct_err) => Err(format!(
            "system proxy download failed; direct download failed: {}",
            direct_err
        )),
    }
}

async fn do_download(url: &str, use_proxy: bool) -> Result<Vec<u8>, String> {
    let client = build_github_client(use_proxy, 120)?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("download read failed: {}", e))
}

fn app_log(msg: &str) {
    let log_p = log_path();
    let is_new = !log_p.exists();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_p)
    {
        use std::io::Write;
        if is_new {
            let _ = file.write_all(b"\xEF\xBB\xBF");
        }
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

    let dir = match crate::path::exe_dir() {
        Some(d) => d,
        None => {
            let e = "Failed to get exe directory".to_string();
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

    // Download the asset: system proxy first, direct fallback
    let bytes = match download_asset(&download_url).await {
        Ok(b) => b,
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(e.clone());
            s.add_log(format!("[ERROR] {}", e));
            app_log(&format!("[ERROR] {}", e));
            crate::service::request_ui_repaint();
            return;
        }
    };

    // Verify download is not empty
    if bytes.is_empty() {
        let msg = "Downloaded file is empty (0 bytes)".to_string();
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Failed(msg.clone());
        s.add_log(format!("[ERROR] {}", msg));
        app_log(&format!("[ERROR] {}", msg));
        crate::service::request_ui_repaint();
        return;
    }

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

    // Verify the written file matches expected size
    match std::fs::metadata(&download_path) {
        Ok(meta) if meta.len() as usize == bytes.len() => {}
        Ok(meta) => {
            let msg = format!(
                "Download size mismatch: expected {} bytes, got {} bytes on disk",
                bytes.len(),
                meta.len()
            );
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(msg.clone());
            s.add_log(format!("[ERROR] {}", msg));
            app_log(&format!("[ERROR] {}", msg));
            crate::service::request_ui_repaint();
            let _ = std::fs::remove_file(&download_path);
            return;
        }
        Err(e) => {
            let msg = format!("Failed to verify downloaded file: {}", e);
            let mut s = state.lock().unwrap();
            s.update_status = UpdateStatus::Failed(msg.clone());
            s.add_log(format!("[ERROR] {}", msg));
            app_log(&format!("[ERROR] {}", msg));
            crate::service::request_ui_repaint();
            return;
        }
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
    [string]$BakExe,
    [string]$LogFile
)

$ErrorActionPreference = "Continue"

function Write-Log($msg) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$stamp $msg" | Out-File -LiteralPath $LogFile -Append -Encoding utf8
}

Write-Log "Updater started"
Write-Log "OldExe=$OldExe"
Write-Log "NewExe=$NewExe"
Write-Log "BakExe=$BakExe"

# Verify the new exe exists and has reasonable size
if (-not (Test-Path -LiteralPath $NewExe)) {
    Write-Log "FATAL: NewExe not found at $NewExe"
    exit 1
}
$newSize = (Get-Item -LiteralPath $NewExe).Length
if ($newSize -lt 102400) {
    Write-Log "FATAL: NewExe too small ($newSize bytes), likely corrupt download"
    exit 1
}
Write-Log "NewExe size: $newSize bytes"

Start-Sleep -Seconds 2
$timeout = 30
while ($timeout -gt 0) {
    $proc = Get-Process -Name "campus-net-client" -ErrorAction SilentlyContinue
    if (-not $proc) { break }
    Write-Log "Waiting for campus-net-client to exit... ($timeout attempts left)"
    Start-Sleep -Seconds 1
    $timeout--
}

if ($timeout -eq 0) {
    Write-Log "WARN: Process still running after 30s timeout, attempting forced replacement"
}

# ── Retry loop for file replacement ──
$maxRetries = 5
$success = $false
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        if (Test-Path -LiteralPath $OldExe) {
            Write-Log "Moving $OldExe -> $BakExe (attempt $i)"
            Move-Item -LiteralPath $OldExe -Destination $BakExe -Force -ErrorAction Stop
        }
        Write-Log "Moving $NewExe -> $OldExe (attempt $i)"
        Move-Item -LiteralPath $NewExe -Destination $OldExe -Force -ErrorAction Stop
        $success = $true
        Write-Log "File replacement succeeded"
        break
    } catch {
        Write-Log "ERROR (attempt $i): $_"
        Start-Sleep -Seconds 2
    }
}

if (-not $success) {
    Write-Log "FATAL: All $maxRetries file replacement attempts failed"
    # Attempt rollback
    if ((Test-Path -LiteralPath $BakExe) -and (-not (Test-Path -LiteralPath $OldExe))) {
        Write-Log "Rolling back: $BakExe -> $OldExe"
        Move-Item -LiteralPath $BakExe -Destination $OldExe -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

# Launch new version
Write-Log "Starting $OldExe"
Start-Process -FilePath $OldExe
Start-Sleep -Seconds 3

# Cleanup
if (Test-Path -LiteralPath $BakExe) {
    Write-Log "Removing backup $BakExe"
    Remove-Item -LiteralPath $BakExe -Force -ErrorAction SilentlyContinue
}

Write-Log "Updater completed successfully"
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
        if let Err(e) = crate::service::config::write_config(config_path(), &s.config) {
            app_log(&format!(
                "[ERROR] Failed to save config before update: {}",
                e
            ));
        }
    }

    let old_exe_str = old_exe.to_string_lossy().to_string();
    let final_path_str = final_path.to_string_lossy().to_string();
    let bak_exe_str = bak_exe.to_string_lossy().to_string();
    let script_path_str = script_path.to_string_lossy().to_string();
    let updater_log_path = dir.join("updater.log");
    let updater_log_str = updater_log_path.to_string_lossy().to_string();

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
            "-LogFile",
            &updater_log_str,
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

    // ── Proxy strategy order tests ────────────────────────

    #[test]
    fn api_check_order_is_direct_then_system() {
        assert_eq!(API_CHECK_ORDER, GithubCheckOrder::DirectThenSystem);
    }

    #[test]
    fn download_order_is_system_then_direct() {
        assert_eq!(DOWNLOAD_ORDER, GithubCheckOrder::SystemThenDirect);
    }

    // ── Rate limit detection tests ────────────────────────

    #[test]
    fn rate_limit_429_is_detected() {
        assert!(is_rate_limit_response(429, ""));
    }

    #[test]
    fn rate_limit_403_with_rate_limit_body_is_detected() {
        assert!(is_rate_limit_response(
            403,
            "API rate limit exceeded for user"
        ));
    }

    #[test]
    fn regular_403_not_detected_as_rate_limit() {
        assert!(!is_rate_limit_response(403, "Not Found"));
    }

    #[test]
    fn regular_200_not_rate_limited() {
        assert!(!is_rate_limit_response(200, ""));
    }

    #[test]
    fn regular_404_not_rate_limited() {
        assert!(!is_rate_limit_response(404, ""));
    }

    // ── Rate limit error formatting tests ─────────────────

    #[test]
    fn format_rate_limit_error_includes_details() {
        let err = format_rate_limit_error(403, "0", "1717200000", "ABC123", "rate limit exceeded");
        assert!(err.contains("403"));
        assert!(err.contains("Remaining: 0"));
        assert!(err.contains("Reset: 1717200000"));
        assert!(err.contains("Request-ID: ABC123"));
        assert!(err.contains("rate limit exceeded"));
    }

    #[test]
    fn format_rate_limit_error_handles_missing_headers() {
        let err = format_rate_limit_error(429, "-", "-", "-", "");
        assert!(err.contains("429"));
        assert!(err.contains("Remaining: -"));
        assert!(err.contains("Reset: -"));
        assert!(err.contains("Request-ID: -"));
    }

    // ── build_github_client tests ─────────────────────────

    #[test]
    fn client_direct_uses_no_proxy() {
        let c = build_github_client(false, 8);
        assert!(c.is_ok());
    }

    #[test]
    fn client_system_proxy_allows_proxy() {
        let c = build_github_client(true, 8);
        assert!(c.is_ok());
    }

    #[test]
    fn user_agent_includes_version() {
        let ua = user_agent();
        assert!(ua.contains("campus-net-client/"));
        assert!(ua.contains("github.com/uchihazzj/campus_net"));
    }
}
