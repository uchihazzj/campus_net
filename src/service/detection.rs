use std::net::Ipv4Addr;
use std::time::Duration;

use crate::core::utils::get_network_interfaces;
use crate::service::{AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus};

// ── Campus IPv4 ────────────────────────────────────────────────────

/// Return all candidate campus IPv4 interfaces (name, ip), filtered to
/// exclude loopback, link-local, and common virtual adapters (VPN, Docker,
/// WSL, Hyper‑V, VMware, etc.). Use this for both IP selection and UI.
pub fn detect_campus_ip_candidates() -> Vec<(String, String)> {
    get_network_interfaces()
        .iter()
        .filter(|(name, ip)| {
            if !ip.is_ipv4() {
                return false;
            }
            let ip_str = ip.to_string();
            if !ip_str.starts_with("10.") {
                return false;
            }
            // Exclude loopback
            if ip.is_loopback() {
                return false;
            }
            // Exclude link-local (169.254.x.x)
            if ip_str.starts_with("169.254.") {
                return false;
            }
            // Exclude common virtual adapter name patterns
            let lower = name.to_lowercase();
            if lower.contains("docker")
                || lower.contains("wsl")
                || lower.contains("hyper-v")
                || lower.contains("vethernet")
                || lower.contains("virtualbox")
                || lower.contains("vmware")
                || lower.contains("vpn")
                || lower.contains("tap")
                || lower.contains("tun")
                || lower.contains("wireguard")
                || lower.contains("tailscale")
                || lower.contains("zerotier")
                || lower.contains("pritunl")
                || lower.contains("openvpn")
                || lower.contains("hamachi")
                || lower.contains("bluestacks")
            {
                tracing::info!("[IP] Skipping virtual adapter: {} (IP={})", name, ip_str);
                return false;
            }
            true
        })
        .map(|(name, ip)| (name.clone(), ip.to_string()))
        .collect()
}

pub fn detect_campus_ip() -> Option<String> {
    let candidates = detect_campus_ip_candidates();
    if candidates.len() > 1 {
        tracing::info!(
            "[IP] Multiple campus IPv4 candidates: {:?}, selecting first",
            candidates
        );
    }
    if candidates.is_empty() {
        tracing::warn!("[IP] No suitable campus IPv4 found");
        None
    } else {
        let (name, ip) = &candidates[0];
        tracing::info!("[IP] Campus IPv4 selected: {} ({})", ip, name);
        Some(ip.clone())
    }
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

    let (client, bound) = match crate::service::http_client::build_probe_client(
        Duration::from_secs(2),
        Duration::from_secs(4),
        campus_ipv4,
    ) {
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
        url,
        campus_ipv4,
        bound
    );

    match client
        .get(&url)
        .query(&[("callback", "sdu"), ("_", &ts)])
        .send()
        .await
    {
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
                e,
                url,
                campus_ipv4,
                bound
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
    let (client, bound) = match crate::service::http_client::build_probe_client(
        Duration::from_secs(2),
        Duration::from_secs(5),
        campus_ipv4,
    ) {
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
        campus_ipv4,
        bound
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
                    status.as_u16(),
                    location
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
                e,
                campus_ipv4,
                bound
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
}

enum SuccessCondition {
    Status200MinLen(usize),
    Status204,
}

static REACHABILITY_CHECKS: &[ReachabilityCheck] = &[
    ReachabilityCheck {
        url: "http://www.baidu.com",
        success: SuccessCondition::Status200MinLen(1000),
    },
    ReachabilityCheck {
        url: "http://connect.rom.miui.com/generate_204",
        success: SuccessCondition::Status204,
    },
    ReachabilityCheck {
        url: "http://www.msftconnecttest.com/connecttest.txt",
        success: SuccessCondition::Status200MinLen(0),
    },
    ReachabilityCheck {
        url: "http://cp.cloudflare.com/",
        success: SuccessCondition::Status200MinLen(0),
    },
];

/// Check IPv4 internet reachability.
///
/// Strategy:
/// 1. Bound probe: bind client to campus_ipv4 via local_address.
/// 2. If bound probe fails, unbound fallback only trusts CaptivePortal
///    (portal redirect is genuine on any IP version); Reachable is treated
///    as ProbeFailed to avoid false positives from IPv6.
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
    // Bound probe failed. Try without local_address to see if the network
    // is completely down or just IPv4-isolated. Only trust CaptivePortal
    // (portal redirect is genuine on any IP version). Treat Reachable as
    // ProbeFailed because it may have succeeded via IPv6 — false positive.
    tracing::info!("[IPv4] Running unbound fallback probe...");
    let unbound_result = run_reachability_probes(None).await;
    match unbound_result {
        Ipv4InternetStatus::CaptivePortal => {
            tracing::info!("[IPv4] Unbound probe confirms captive portal");
            Ipv4InternetStatus::CaptivePortal
        }
        Ipv4InternetStatus::Reachable => {
            tracing::warn!(
                "[IPv4] Unbound probe succeeded but cannot confirm IPv4 — treating as ProbeFailed"
            );
            Ipv4InternetStatus::ProbeFailed
        }
        other => other,
    }
}

/// Run the full set of reachability checks with an optional local_address binding.
async fn run_reachability_probes(local_v4: Option<Ipv4Addr>) -> Ipv4InternetStatus {
    let ip_str = local_v4.map(|a| a.to_string());
    let (client, bound) = match crate::service::http_client::build_probe_client(
        Duration::from_secs(2),
        Duration::from_secs(3),
        ip_str.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "[IPv4] Failed to build client: {} bound={}",
                e,
                local_v4.is_some()
            );
            return Ipv4InternetStatus::ProbeFailed;
        }
    };

    let mut last_error = String::new();

    for check in REACHABILITY_CHECKS {
        match try_single_check(&client, check).await {
            Ok(()) => {
                tracing::info!("[IPv4] Reachable via: {} bound={}", check.url, bound);
                return Ipv4InternetStatus::Reachable;
            }
            Err(CheckError::CaptivePortal { url, location }) => {
                tracing::info!(
                    "[IPv4] CaptivePortal: {} → location={} bound={}",
                    url,
                    location,
                    bound
                );
                return Ipv4InternetStatus::CaptivePortal;
            }
            Err(CheckError::Failed { url, detail }) => {
                tracing::debug!("[IPv4] Failed: {} detail={} bound={}", url, detail, bound);
                last_error = format!("{}: {}", url, detail);
            }
        }
    }

    tracing::warn!(
        "[IPv4] All probes failed. last_error={} bound={}",
        last_error,
        bound
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
    let resp = client
        .get(check.url)
        .send()
        .await
        .map_err(|e| CheckError::Failed {
            url: check.url,
            detail: format!("request error: {}", e),
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
            let body = resp.bytes().await.map_err(|e| CheckError::Failed {
                url: check.url,
                detail: format!("body read error: {}", e),
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
