use std::net::Ipv4Addr;
use std::time::Duration;

use crate::core::utils::get_network_interfaces;
use crate::service::{AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus};

// ── Campus IPv4 ────────────────────────────────────────────────────

pub fn detect_campus_ip() -> Option<String> {
    get_network_interfaces()
        .iter()
        .filter(|(_, ip)| ip.is_ipv4())
        .map(|(_, ip)| ip.to_string())
        .find(|ip| ip.starts_with("10."))
}

// ── Auth Server Reachability ───────────────────────────────────────
// Only reflects whether the configured Srun auth server (e.g.
// http://10.0.0.55) is reachable. Does NOT probe the public internet.

/// Probe the actual Srun auth server by calling its /cgi-bin/get_challenge
/// endpoint. Any HTTP response (including JSON error) counts as reachable.
/// Only a TCP connection failure means the server is unreachable.
pub async fn check_auth_server(server: &str, campus_ipv4: Option<&str>) -> AuthServerStatus {
    let server = crate::core::srun::SrunClient::normalize_server_url(server);
    if server.is_empty() {
        tracing::warn!("[AuthServer] No server URL configured");
        return AuthServerStatus::Unknown;
    }

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    let bound = if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            builder = builder.local_address(std::net::IpAddr::V4(addr));
            true
        } else {
            false
        }
    } else {
        false
    };

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[AuthServer] Failed to build client: {}", e);
            return AuthServerStatus::Unknown;
        }
    };

    let url = format!("{}/cgi-bin/get_challenge", server);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    tracing::info!(
        "[AuthServer] Probing: url={} campus_ipv4={:?} bound={}",
        url, campus_ipv4, bound
    );

    match client.get(&url).query(&[("callback", "sdu"), ("_", &ts)]).send().await {
        Ok(resp) => {
            let status = resp.status();
            tracing::info!(
                "[AuthServer] Reachable: status={} campus_ipv4={:?}",
                status.as_u16(),
                campus_ipv4
            );
            AuthServerStatus::Reachable
        }
        Err(e) => {
            tracing::warn!(
                "[AuthServer] Unreachable: error={} url={} campus_ipv4={:?} bound={}",
                e, url, campus_ipv4, bound
            );
            AuthServerStatus::Unreachable
        }
    }
}

// ── Captive Portal Probe (Auth Status) ─────────────────────────────
// Determines login state by detecting whether the campus gateway
// redirects HTTP requests to the portal login page.
// This is NOT an auth server check — it's a captive portal probe.
// If the probe itself fails, the result is Unknown, not "server unreachable".

/// Check login status via captive portal probe: send an HTTP request to an
/// external URL. If the campus gateway redirects to the portal → NotLoggedIn.
/// If the request succeeds without redirect → LoggedIn.
/// If the probe fails entirely (DNS, timeout, etc.) → Unknown.
pub async fn check_auth_status(campus_ipv4: Option<&str>) -> CampusAuthStatus {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    let bound = if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            builder = builder.local_address(std::net::IpAddr::V4(addr));
            true
        } else {
            false
        }
    } else {
        false
    };

let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[CaptiveProbe] Failed to build client: {}", e);
            return CampusAuthStatus::Unknown;
        }
    };

    // Use a well-known HTTP URL. The campus gateway will redirect to the
    // portal if not logged in.
    tracing::info!(
        "[CaptiveProbe] Probing http://www.baidu.com campus_ipv4={:?} bound={}",
        campus_ipv4, bound
    );

    match client.get("http://www.baidu.com").send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                tracing::info!("[CaptiveProbe] LoggedIn: status={}", status.as_u16());
                return CampusAuthStatus::LoggedIn;
            }
            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("(missing)");
                if is_portal_url(location) {
                    tracing::info!(
                        "[CaptiveProbe] NotLoggedIn: portal redirect location={}",
                        location
                    );
                    return CampusAuthStatus::NotLoggedIn;
                }
                // Non-portal redirect (e.g., http→https upgrade) → logged in
                tracing::info!(
                    "[CaptiveProbe] LoggedIn (non-portal redirect): status={} location={}",
                    status.as_u16(), location
                );
                return CampusAuthStatus::LoggedIn;
            }
            tracing::info!(
                "[CaptiveProbe] Unknown: unexpected status={}",
                status.as_u16()
            );
            CampusAuthStatus::Unknown
        }
        Err(e) => {
            // Probe failed — NOT "server unreachable"
            tracing::warn!(
                "[CaptiveProbe] Probe failed (Unknown): error={} campus_ipv4={:?} bound={}",
                e, campus_ipv4, bound
            );
            CampusAuthStatus::Unknown
        }
    }
}

fn is_portal_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("srun_portal")
        || lower.contains("ac_id=")
        || lower.contains("userip=")
        || lower.contains("wlanuserip")
        || lower.contains("redirect")
        || lower.contains("portal")
        || lower.contains("login")
}

// ── IPv4 Internet Reachability ─────────────────────────────────────

struct ReachabilityCheck {
    url: &'static str,
    success: SuccessCondition,
    /// Prefer this endpoint for unbound fallback (more stable domestically)
    preferred: bool,
}

enum SuccessCondition {
    Status200MinLen(usize),
    Status204,
}

/// Ordered by domestic stability. Preferred endpoints tried first in unbound fallback.
static REACHABILITY_CHECKS: &[ReachabilityCheck] = &[
    ReachabilityCheck {
        url: "http://www.baidu.com",
        success: SuccessCondition::Status200MinLen(1000),
        preferred: true,
    },
    ReachabilityCheck {
        url: "http://connect.rom.miui.com/generate_204",
        success: SuccessCondition::Status204,
        preferred: true,
    },
    ReachabilityCheck {
        url: "http://www.msftconnecttest.com/connecttest.txt",
        success: SuccessCondition::Status200MinLen(0),
        preferred: false,
    },
    ReachabilityCheck {
        url: "http://cp.cloudflare.com/",
        success: SuccessCondition::Status200MinLen(0),
        preferred: false,
    },
];

/// Check IPv4 internet reachability.
///
/// Strategy:
/// 1. Bound probe: bind client to campus_ipv4 via local_address.
/// 2. If all bound probes fail, attempt unbound IPv4 probe as fallback.
/// 3. Log every endpoint result for diagnostics.
///
/// Returns `ProbeFailed` if the client can't be built at all.
pub async fn check_ipv4_reachability(campus_ipv4: Option<&str>) -> Ipv4InternetStatus {
    // ── Bound probe ────────────────────────────────────
    if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let bound_result = run_reachability_probes(Some(addr)).await;
            match bound_result {
                Ipv4InternetStatus::Reachable | Ipv4InternetStatus::CaptivePortal => {
                    return bound_result;
                }
                _ => {
                    tracing::warn!(
                        "[IPv4] Bound probe failed (campus_ipv4={}), trying unbound fallback...",
                        ip
                    );
                }
            }
        }
    }

    // ── Unbound fallback ───────────────────────────────
    // Try without local_address, preferring domestic endpoints.
    // Request still goes over whatever route the system chooses;
    // in a dual-stack environment this may go over IPv6, so a
    // "Reachable" here is less trustworthy.
    tracing::info!("[IPv4] Running unbound fallback probe...");
    let unbound_result = run_reachability_probes(None).await;
    if matches!(unbound_result, Ipv4InternetStatus::Reachable) {
        tracing::info!("[IPv4] Unbound probe succeeded (may have used IPv6!)");
    }
    unbound_result
}

/// Run the full set of reachability checks with an optional local_address binding.
async fn run_reachability_probes(local_v4: Option<Ipv4Addr>) -> Ipv4InternetStatus {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    let bound = if let Some(addr) = local_v4 {
        builder = builder.local_address(std::net::IpAddr::V4(addr));
        true
    } else {
        false
    };

let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[IPv4] Failed to build client: {} bound={}", e, bound);
            return Ipv4InternetStatus::ProbeFailed;
        }
    };

    let mut last_error = String::new();

    for check in REACHABILITY_CHECKS {
        match try_single_check(&client, check).await {
            Ok(()) => {
                tracing::info!(
                    "[IPv4] Reachable via: {} bound={}",
                    check.url, bound
                );
                return Ipv4InternetStatus::Reachable;
            }
            Err(CheckError::CaptivePortal { url, location }) => {
                tracing::info!(
                    "[IPv4] CaptivePortal: {} → location={} bound={}",
                    url, location, bound
                );
                return Ipv4InternetStatus::CaptivePortal;
            }
            Err(CheckError::Failed { url, detail }) => {
                tracing::debug!(
                    "[IPv4] Failed: {} detail={} bound={}",
                    url, detail, bound
                );
                last_error = format!("{}: {}", url, detail);
            }
        }
    }

    tracing::warn!(
        "[IPv4] All probes failed. last_error={} bound={}",
        last_error, bound
    );
    Ipv4InternetStatus::Unreachable
}

enum CheckError {
    CaptivePortal { url: &'static str, location: String },
    Failed { url: &'static str, detail: String },
}

async fn try_single_check(
    client: &reqwest::Client,
    check: &ReachabilityCheck,
) -> Result<(), CheckError> {
    let resp = client.get(check.url).send().await.map_err(|e| {
        CheckError::Failed {
            url: check.url,
            detail: format!("request error: {}", e),
        }
    })?;

    let status = resp.status();

    // Check for captive portal redirect
    if status.is_redirection() {
        if let Some(location) = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            if is_portal_url(location) {
                return Err(CheckError::CaptivePortal {
                    url: check.url,
                    location: location.to_string(),
                });
            }
        }
    }

    match check.success {
        SuccessCondition::Status204 => {
            if status.as_u16() == 204 {
                Ok(())
            } else {
                Err(CheckError::Failed {
                    url: check.url,
                    detail: format!("expected 204, got {}", status.as_u16()),
                })
            }
        }
        SuccessCondition::Status200MinLen(min_len) => {
            if !status.is_success() {
                return Err(CheckError::Failed {
                    url: check.url,
                    detail: format!("expected 200, got {}", status.as_u16()),
                });
            }
            if min_len == 0 {
                return Ok(());
            }
            let body = resp.bytes().await.map_err(|e| {
                CheckError::Failed {
                    url: check.url,
                    detail: format!("body read error: {}", e),
                }
            })?;
            if body.len() >= min_len {
                Ok(())
            } else {
                Err(CheckError::Failed {
                    url: check.url,
                    detail: format!("body too short: {} < {}", body.len(), min_len),
                })
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_campus_ip() {
        let ip = detect_campus_ip();
        println!("Campus IPv4: {:?}", ip);
    }

    #[tokio::test]
    async fn test_check_auth_server() {
        let ip = detect_campus_ip();
        let status = check_auth_server("http://10.0.0.55", ip.as_deref()).await;
        println!("Auth server: {:?}", status);
    }

    #[tokio::test]
    async fn test_check_auth_status() {
        let ip = detect_campus_ip();
        let status = check_auth_status(ip.as_deref()).await;
        println!("Auth status: {:?}", status);
    }

    #[tokio::test]
    async fn test_check_ipv4_reachability() {
        let ip = detect_campus_ip();
        let result = check_ipv4_reachability(ip.as_deref()).await;
        println!("IPv4 reachability: {:?}", result);
    }
}
