use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Idle,
    Checking,
    UpToDate,
    Available { latest: String, url: String },
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
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
/// Returns Some((latest_version, url)) if an update is available,
/// None if up to date, or Err(message) if the check failed.
pub async fn check_update() -> Result<Option<(String, String)>, String> {
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

    if is_newer(local, &release.tag_name) {
        Ok(Some((release.tag_name, release.html_url)))
    } else {
        Ok(None)
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
        // Equal versions (no leading v mismatch)
        assert!(!is_newer("0.2.1", "0.2.1"));
    }
}
