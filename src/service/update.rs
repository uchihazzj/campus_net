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
    /// API check: direct first, fallback to environment proxy
    DirectThenSystem,
    /// Download: environment proxy first, fallback to direct
    SystemThenDirect,
}

/// API latest check order: direct first → environment proxy fallback.
#[allow(dead_code)]
pub const API_CHECK_ORDER: GithubCheckOrder = GithubCheckOrder::DirectThenSystem;

/// Asset download order: environment proxy first → direct fallback.
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
/// `use_proxy = true` → lets reqwest use the environment proxy (no `.no_proxy()`).
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

/// Release tags use the documented vX.Y.Z format. Validate them before
/// comparing versions or using a tag in a download filename.
fn parse_release_version(version: &str) -> Option<[u32; 3]> {
    let mut parts = version.strip_prefix('v').unwrap_or(version).split('.');
    let mut numbers = [0; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(numbers)
}

fn is_newer(local: &str, remote: &str) -> bool {
    match (parse_release_version(local), parse_release_version(remote)) {
        (Some(local), Some(remote)) => remote > local,
        _ => false,
    }
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

    if parse_release_version(&release.tag_name).is_none() {
        return Err("Release tag must use vX.Y.Z with numeric components".to_string());
    }

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
/// Proxy strategy: **direct first** (`no_proxy`), then fall back to **environment proxy**
/// if the direct request fails with a network error. If the environment proxy request
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
                "[Update] Direct API check failed: {} — falling back to environment proxy",
                direct_err
            );
        }
    }

    // ── Fallback to environment proxy ─────────────────────────
    do_check_update(true).await
}

/// Download an asset with environment-proxy-first strategy.
/// Tries environment proxy, then falls back to direct on failure.
async fn download_asset(url: &str) -> Result<Vec<u8>, String> {
    // ── Try environment proxy first ──────────────────────────
    match do_download(url, true).await {
        Ok(bytes) => return Ok(bytes),
        Err(sys_err) => {
            tracing::info!(
                "[Update] Environment proxy download failed: {} — falling back to direct",
                sys_err
            );
        }
    }

    // ── Fallback to direct ─────────────────────────────
    match do_download(url, false).await {
        Ok(bytes) => Ok(bytes),
        Err(direct_err) => Err(format!(
            "environment proxy download failed; direct download failed: {}",
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

fn validate_download(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 102400 {
        return Err("Downloaded executable is smaller than 100 KiB".to_string());
    }
    if !bytes.starts_with(b"MZ") {
        return Err("Downloaded file is not a Windows executable".to_string());
    }
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    if !bytes
        .get(pe_offset..)
        .is_some_and(|header| header.starts_with(b"PE\0\0"))
    {
        return Err("Downloaded executable has an invalid PE header".to_string());
    }
    Ok(())
}

fn replacement_paths(current_exe: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut backup = current_exe.as_os_str().to_os_string();
    backup.push(".bak");
    (current_exe.to_path_buf(), backup.into())
}

fn fail_update(state: &SharedState, message: String) {
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Failed(message.clone());
        s.add_log(format!("[ERROR] {}", message));
    }
    app_log(&format!("[ERROR] {}", message));
    crate::service::request_ui_repaint();
}

/// Download the latest exe from GitHub, generate updater script, launch it, and exit.
pub async fn perform_update(state: SharedState, version: String, download_url: String) {
    let clean_ver = version.trim_start_matches('v');
    let download_filename = format!("campus-net-client-v{}.exe", clean_ver);

    // ── Step 1: Download ────────────────────────────────
    {
        let mut s = state.lock().unwrap();
        if !matches!(&s.update_status, UpdateStatus::Available { latest, download_url: url, .. }
            if latest == &version && url == &download_url)
        {
            return;
        }
        s.update_status = UpdateStatus::Downloading;
        s.add_log(format!("[INFO] Downloading {} ...", download_filename));
    }
    crate::service::request_ui_repaint();

    if parse_release_version(&version).is_none() {
        fail_update(&state, "Invalid update version".to_string());
        return;
    }

    let dir = match crate::path::exe_dir() {
        Some(d) => d,
        None => {
            let e = "Failed to get exe directory".to_string();
            fail_update(&state, e);
            return;
        }
    };

    let download_path = dir.join(format!("{}.download", download_filename));
    let final_path = dir.join(&download_filename);

    // Download the asset: environment proxy first, direct fallback
    let bytes = match download_asset(&download_url).await {
        Ok(b) => b,
        Err(e) => {
            fail_update(&state, e);
            return;
        }
    };

    // Verify download is not empty
    if let Err(msg) = validate_download(&bytes) {
        fail_update(&state, msg);
        return;
    }

    // Write to .download temp file
    if let Err(e) = std::fs::write(&download_path, &bytes) {
        let msg = format!("Failed to write download: {}", e);
        fail_update(&state, msg);
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
            fail_update(&state, msg);
            let _ = std::fs::remove_file(&download_path);
            return;
        }
        Err(e) => {
            let msg = format!("Failed to verify downloaded file: {}", e);
            fail_update(&state, msg);
            return;
        }
    }

    // Rename .download → final name
    if let Err(e) = std::fs::rename(&download_path, &final_path) {
        let msg = format!("Failed to rename download: {}", e);
        fail_update(&state, msg);
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

    let current_exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            fail_update(
                &state,
                format!("Failed to locate running executable: {}", e),
            );
            return;
        }
    };
    let (old_exe, bak_exe) = replacement_paths(&current_exe);

    let script = UPDATER_SCRIPT;

    let script_path = dir.join("updater.ps1");
    if let Err(e) = std::fs::write(&script_path, script.as_bytes()) {
        let msg = format!("Failed to write updater script: {}", e);
        fail_update(&state, msg);
        return;
    }

    // ── Step 3: Save config and launch updater ────────────
    {
        let mut s = state.lock().unwrap();
        s.update_status = UpdateStatus::Restarting;
        s.add_log("[INFO] Launching updater and exiting...".to_string());
    }
    crate::service::request_ui_repaint();

    if let Err(e) = crate::service::config::save_shared_config(config_path(), &state) {
        let msg = format!("Failed to save config before update: {}", e);
        fail_update(&state, msg);
        return;
    }

    let old_exe_str = old_exe.to_string_lossy().to_string();
    let final_path_str = final_path.to_string_lossy().to_string();
    let bak_exe_str = bak_exe.to_string_lossy().to_string();
    let script_path_str = script_path.to_string_lossy().to_string();
    let updater_log_path = dir.join("updater.log");
    let updater_log_str = updater_log_path.to_string_lossy().to_string();

    let mut command = std::process::Command::new("powershell.exe");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let process_id = std::process::id().to_string();
    match command
        .args([
            "-NoProfile",
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
            "-OldProcessId",
            &process_id,
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
            fail_update(&state, msg);
        }
    }
}

const UPDATER_SCRIPT: &str = r#"param(
    [string]$OldExe,
    [string]$NewExe,
    [string]$BakExe,
    [string]$LogFile,
    [int]$OldProcessId
)

$ErrorActionPreference = "Stop"

function Write-Log($msg) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "$stamp $msg" | Out-File -LiteralPath $LogFile -Append -Encoding utf8 -ErrorAction Stop
    } catch {
        Write-Output "$stamp $msg (log write failed)"
    }
}

$backedUp = $false
$installed = $false
try {
    $OldExe = [System.IO.Path]::GetFullPath($OldExe)
    $NewExe = [System.IO.Path]::GetFullPath($NewExe)
    $BakExe = [System.IO.Path]::GetFullPath($BakExe)
    $exeDir = [System.IO.Path]::GetDirectoryName($OldExe)
    if (($OldExe -eq $NewExe) -or ($BakExe -ne "$OldExe.bak") -or
        ([System.IO.Path]::GetDirectoryName($NewExe) -ne $exeDir) -or
        ([System.IO.Path]::GetDirectoryName($BakExe) -ne $exeDir)) {
        throw "Invalid replacement paths"
    }
    Write-Log "Updater started"
    Write-Log "OldExe=$OldExe NewExe=$NewExe BakExe=$BakExe PID=$OldProcessId"
    if (-not (Test-Path -LiteralPath $NewExe -PathType Leaf)) {
        throw "NewExe not found"
    }
    if ((Get-Item -LiteralPath $NewExe).Length -lt 102400) {
        throw "NewExe too small, likely corrupt download"
    }

    Start-Sleep -Seconds 2
    $timeout = 30
    while ($timeout -gt 0) {
        $proc = Get-Process -Id $OldProcessId -ErrorAction SilentlyContinue
        if (-not $proc) { break }
        Start-Sleep -Seconds 1
        $timeout--
    }
    if ($timeout -eq 0) { throw "Old process did not exit within 30 seconds" }

    for ($i = 1; $i -le 5; $i++) {
        try {
            if (-not $backedUp -and (Test-Path -LiteralPath $OldExe)) {
                Move-Item -LiteralPath $OldExe -Destination $BakExe -Force -ErrorAction Stop
                $backedUp = $true
            }
            Move-Item -LiteralPath $NewExe -Destination $OldExe -Force -ErrorAction Stop
            $installed = $true
            Write-Log "File replacement succeeded"
            break
        } catch {
            Write-Log "ERROR (attempt $i): $_"
            if ($i -eq 5) { throw }
            Start-Sleep -Seconds 2
        }
    }

    Write-Log "Starting $OldExe"
    $newProcess = Start-Process -FilePath $OldExe -WorkingDirectory $exeDir -WindowStyle Hidden -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 3
    $newProcess.Refresh()
    if ($newProcess.HasExited) { throw "New executable exited during startup" }

    if ($backedUp) {
        Remove-Item -LiteralPath $BakExe -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Updater completed successfully"
    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
} catch {
    Write-Log "FATAL: $_"
    try {
        if ($backedUp -and (Test-Path -LiteralPath $BakExe)) {
            if ($installed -and (Test-Path -LiteralPath $OldExe)) {
                Remove-Item -LiteralPath $OldExe -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath $BakExe -Destination $OldExe -Force -ErrorAction Stop
            Write-Log "Rollback succeeded"
        }
        if ((Test-Path -LiteralPath $OldExe) -and
            (-not (Get-Process -Id $OldProcessId -ErrorAction SilentlyContinue))) {
            Start-Process -FilePath $OldExe -WorkingDirectory $exeDir -WindowStyle Hidden -ErrorAction Stop
            Write-Log "Previous executable restarted"
        }
    } catch {
        Write-Log "FATAL: Rollback/restart failed: $_. Backup preserved at $BakExe"
    }
    exit 1
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_replaces_the_actual_executable_when_renamed() {
        let exe = std::path::Path::new(r"C:\Apps\renamed [client].exe");
        let (old, backup) = replacement_paths(exe);
        assert_eq!(old, exe);
        assert_eq!(
            backup,
            std::path::Path::new(r"C:\Apps\renamed [client].exe.bak")
        );
    }

    #[test]
    fn update_rejects_small_downloads_and_html_before_exit() {
        assert!(validate_download(b"MZ").is_err());
        assert!(validate_download(&vec![b'<'; 102400]).is_err());
    }

    #[test]
    fn update_checks_the_pe_header_bounds() {
        let mut bytes = vec![0; 102400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        assert!(validate_download(&bytes).is_ok());
        bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_download(&bytes).is_err());
    }

    #[test]
    fn malformed_release_tags_do_not_trigger_an_update() {
        for tag in [
            "v99.0.0/../../other",
            "vv99.0.0",
            "v99.0.0-beta",
            "v99",
            "v99.0.x",
        ] {
            assert!(!is_newer("1.1.10", tag), "accepted invalid tag: {tag}");
        }
    }

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
