use std::net::Ipv4Addr;
use std::time::Duration;

use crate::service::{AuthServerStatus, CampusAuthStatus, Ipv4InternetStatus};

// ── Campus IPv4 ────────────────────────────────────────────────────

/// Return all candidate campus IPv4 interfaces (name, ip), filtered to
/// exclude loopback, link-local, and common virtual adapters (VPN, Docker,
/// WSL, Hyper‑V, VMware, etc.). Use this for both IP selection and UI.
pub fn campus_ip_candidates_from_interfaces(
    interfaces: &[(String, std::net::IpAddr)],
) -> Vec<(String, String)> {
    interfaces
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
                tracing::debug!("[IP] Skipping virtual adapter: {} (IP={})", name, ip_str);
                return false;
            }
            true
        })
        .map(|(name, ip)| (name.clone(), ip.to_string()))
        .collect()
}

pub fn detect_campus_ip_from_interfaces(
    interfaces: &[(String, std::net::IpAddr)],
) -> Option<String> {
    let candidates = campus_ip_candidates_from_interfaces(interfaces);
    if candidates.len() > 1 {
        tracing::debug!(
            "[IP] Multiple campus IPv4 candidates: {:?}, selecting first",
            candidates
        );
    }
    if candidates.is_empty() {
        tracing::warn!("[IP] No suitable campus IPv4 found");
        None
    } else {
        let (name, ip) = &candidates[0];
        tracing::debug!("[IP] Campus IPv4 selected: {} ({})", ip, name);
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
        .unwrap_or_default()
        .as_secs()
        .to_string();

    tracing::debug!(
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
            tracing::debug!(
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
/// Without a valid campus IPv4 source, skip the request and return Unknown.
pub async fn check_auth_status(server: &str, campus_ipv4: Option<&str>) -> CampusAuthStatus {
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

    if !bound {
        tracing::debug!("[CaptiveProbe] No campus IPv4 binding; skipping auth probe");
        return CampusAuthStatus::Unknown;
    }

    // Use a well-known HTTP URL. The campus gateway will redirect to the
    // portal if not logged in.
    tracing::debug!(
        "[CaptiveProbe] Probing http://www.baidu.com campus_ipv4={:?} bound={}",
        campus_ipv4,
        bound
    );

    match client.get("http://www.baidu.com").send().await {
        Ok(resp) => {
            let auth_status = auth_status_from_probe_response(
                bound,
                resp.status(),
                resp.headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                resp.url(),
                server,
            );
            tracing::debug!(
                "[CaptiveProbe] Response status={} auth_status={:?} bound={}",
                resp.status().as_u16(),
                auth_status,
                bound
            );
            auth_status
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

fn auth_status_from_probe_response(
    bound: bool,
    status: reqwest::StatusCode,
    location: Option<&str>,
    request_url: &reqwest::Url,
    server: &str,
) -> CampusAuthStatus {
    if !bound {
        return CampusAuthStatus::Unknown;
    }
    if status.is_success() {
        return CampusAuthStatus::LoggedIn;
    }
    if status.is_redirection() {
        if location.is_some_and(|url| is_portal_url(url, request_url, server)) {
            return CampusAuthStatus::NotLoggedIn;
        }
        return CampusAuthStatus::LoggedIn;
    }
    CampusAuthStatus::Unknown
}

fn is_portal_url(location: &str, request_url: &reqwest::Url, server: &str) -> bool {
    let Ok(target) = request_url.join(location) else {
        return false;
    };
    if !matches!(target.scheme(), "http" | "https") {
        return false;
    }
    let server = crate::core::srun::SrunClient::normalize_server_url(server);
    if reqwest::Url::parse(&server)
        .ok()
        .is_some_and(|auth| auth.host_str().is_some() && auth.host_str() == target.host_str())
    {
        return true;
    }

    // Ordinary websites also use login/redirect/portal. Only Srun-specific
    // paths or the paired portal parameters establish a campus redirect.
    target
        .path()
        .split('/')
        .any(|part| part.eq_ignore_ascii_case("srun_portal"))
        || (target
            .query_pairs()
            .any(|(key, _)| key.eq_ignore_ascii_case("ac_id"))
            && target.query_pairs().any(|(key, _)| {
                key.eq_ignore_ascii_case("userip") || key.eq_ignore_ascii_case("wlanuserip")
            }))
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
/// 2. If bound probe fails, an unbound response cannot establish the campus
///    IPv4 state: it may travel through TUN, IPv6, or another adapter.
///    Both success and portal redirects are treated as ProbeFailed.
///
/// Returns `ProbeFailed` if the client can't be built at all.
pub async fn check_ipv4_reachability(
    server: &str,
    campus_ipv4: Option<&str>,
) -> Ipv4InternetStatus {
    // ── Bound probe ────────────────────────────────────
    if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let bound_result = run_reachability_probes(server, Some(addr)).await;
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
    // Keep the diagnostic fallback, but do not authenticate the campus session
    // from another route after its source-address binding failed.
    tracing::debug!("[IPv4] Running unbound fallback probe...");
    let unbound_result = run_reachability_probes(server, None).await;
    unbound_probe_status(unbound_result)
}

fn unbound_probe_status(unbound_result: Ipv4InternetStatus) -> Ipv4InternetStatus {
    match unbound_result {
        Ipv4InternetStatus::Reachable | Ipv4InternetStatus::CaptivePortal => {
            tracing::warn!(
                "[IPv4] Unbound response cannot confirm the campus IPv4 state — treating as ProbeFailed"
            );
            Ipv4InternetStatus::ProbeFailed
        }
        other => other,
    }
}

/// Run the full set of reachability checks with an optional local_address binding.
async fn run_reachability_probes(server: &str, local_v4: Option<Ipv4Addr>) -> Ipv4InternetStatus {
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
        match try_single_check(&client, check, server).await {
            Ok(()) => {
                tracing::debug!("[IPv4] Reachable via: {} bound={}", check.url, bound);
                return Ipv4InternetStatus::Reachable;
            }
            Err(CheckError::CaptivePortal { url, location }) => {
                tracing::debug!(
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
    server: &str,
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
            if is_portal_url(location, resp.url(), server) {
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
    fn ordinary_site_redirects_are_not_campus_portals() {
        let request = reqwest::Url::parse("http://www.baidu.com").unwrap();
        for location in [
            "https://example.com/account/login",
            "https://example.com/?redirect=/news",
            "https://portal.example.com/",
            "https://example.com/?next=http%3A%2F%2F10.0.0.55%2Flogin",
        ] {
            assert!(
                !is_portal_url(location, &request, "http://10.0.0.55"),
                "ordinary redirect: {location}"
            );
        }
    }

    #[test]
    fn srun_portal_redirects_are_recognized() {
        let request = reqwest::Url::parse("http://www.baidu.com").unwrap();
        for location in [
            "http://10.0.0.55/index_1.html",
            "http://10.0.0.56/cgi-bin/srun_portal",
            "http://10.0.0.56/index_1.html?ac_id=8&userip=10.0.0.2",
            "/cgi-bin/srun_portal",
        ] {
            assert!(
                is_portal_url(location, &request, "http://10.0.0.55"),
                "campus redirect: {location}"
            );
        }
    }

    #[test]
    fn unbound_routes_cannot_establish_the_campus_ipv4_authentication_state() {
        for status in [
            Ipv4InternetStatus::Reachable,
            Ipv4InternetStatus::CaptivePortal,
        ] {
            assert_eq!(
                unbound_probe_status(status),
                Ipv4InternetStatus::ProbeFailed
            );
        }
        assert_eq!(
            unbound_probe_status(Ipv4InternetStatus::Unreachable),
            Ipv4InternetStatus::Unreachable
        );
    }

    #[test]
    fn probe_results_require_a_bound_campus_source() {
        let request = reqwest::Url::parse("http://www.baidu.com").unwrap();
        for (status, location, expected_bound) in [
            (reqwest::StatusCode::OK, None, CampusAuthStatus::LoggedIn),
            (
                reqwest::StatusCode::FOUND,
                Some("http://10.0.0.55/index_1.html"),
                CampusAuthStatus::NotLoggedIn,
            ),
        ] {
            assert_eq!(
                auth_status_from_probe_response(
                    false,
                    status,
                    location,
                    &request,
                    "http://10.0.0.55"
                ),
                CampusAuthStatus::Unknown
            );
            assert_eq!(
                auth_status_from_probe_response(
                    true,
                    status,
                    location,
                    &request,
                    "http://10.0.0.55"
                ),
                expected_bound
            );
        }
    }

    #[test]
    fn campus_ip_detection_uses_only_the_supplied_local_addresses() {
        let mut interfaces = vec![
            ("test-tun".into(), "10.0.0.1".parse().unwrap()),
            ("test-local".into(), "192.168.137.1".parse().unwrap()),
            ("test-ipv6".into(), "::1".parse().unwrap()),
        ];
        assert!(detect_campus_ip_from_interfaces(&interfaces).is_none());
        interfaces.push(("test-campus".into(), "10.0.0.2".parse().unwrap()));
        assert_eq!(
            detect_campus_ip_from_interfaces(&interfaces).as_deref(),
            Some("10.0.0.2")
        );
        assert!(detect_campus_ip_from_interfaces(&[]).is_none());
    }

    #[tokio::test]
    #[ignore = "manual network test; contacts the campus authentication server"]
    async fn test_check_auth_server() {
        let ip = detect_campus_ip_from_interfaces(&crate::core::utils::get_network_interfaces());
        let status = check_auth_server("http://10.0.0.55", ip.as_deref()).await;
        println!("Auth server: {:?}", status);
    }

    #[tokio::test]
    #[ignore = "manual network test; contacts the public internet"]
    async fn test_check_auth_status() {
        let ip = detect_campus_ip_from_interfaces(&crate::core::utils::get_network_interfaces());
        let status = check_auth_status("http://10.0.0.55", ip.as_deref()).await;
        println!("Auth status: {:?}", status);
    }

    #[tokio::test]
    #[ignore = "manual network test; contacts the public internet"]
    async fn test_check_ipv4_reachability() {
        let ip = detect_campus_ip_from_interfaces(&crate::core::utils::get_network_interfaces());
        let result = check_ipv4_reachability("http://10.0.0.55", ip.as_deref()).await;
        println!("IPv4 reachability: {:?}", result);
    }
}
