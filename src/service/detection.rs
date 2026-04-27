use std::net::Ipv4Addr;
use std::time::Duration;

use crate::core::utils::get_network_interfaces;
use crate::service::Ipv4InternetStatus;

// ── Campus IPv4 Detection ──────────────────────────────────────────

pub fn detect_campus_ip() -> Option<String> {
    get_network_interfaces()
        .iter()
        .filter(|(_, ip)| ip.is_ipv4())
        .map(|(_, ip)| ip.to_string())
        .find(|ip| ip.starts_with("10."))
}

// ── Campus Auth Status ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum CampusAuthStatus {
    LoggedIn,
    NotLoggedIn,
    ServerUnreachable,
    Unknown,
}

/// Check campus auth by sending an HTTP request via the campus IPv4 interface.
/// Binds to `campus_ipv4` to force IPv4, avoiding IPv6 false-positive.
pub async fn check_auth_status(campus_ipv4: Option<&str>) -> CampusAuthStatus {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            builder = builder.local_address(std::net::IpAddr::V4(addr));
        }
    }

let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to build auth check client: {}", e);
            return CampusAuthStatus::Unknown;
        }
    };

    match client.get("http://www.baidu.com").send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                return CampusAuthStatus::LoggedIn;
            }
            if status.is_redirection() {
                if let Some(location) = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    if is_portal_url(location) {
                        return CampusAuthStatus::NotLoggedIn;
                    }
                }
                return CampusAuthStatus::LoggedIn;
            }
            CampusAuthStatus::Unknown
        }
        Err(e) => {
            tracing::debug!("Auth check request failed: {}", e);
            CampusAuthStatus::ServerUnreachable
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
    Status(u16),
    Status200MinLen(usize),
    Status204,
}

static REACHABILITY_CHECKS: &[ReachabilityCheck] = &[
    ReachabilityCheck {
        url: "https://www.baidu.com",
        success: SuccessCondition::Status200MinLen(1000),
    },
    ReachabilityCheck {
        url: "http://cp.cloudflare.com/",
        success: SuccessCondition::Status200MinLen(0),
    },
    ReachabilityCheck {
        url: "http://www.gstatic.com/generate_204",
        success: SuccessCondition::Status204,
    },
    ReachabilityCheck {
        url: "http://connect.rom.miui.com/generate_204",
        success: SuccessCondition::Status204,
    },
];

/// Check IPv4 internet reachability by forcing the HTTP client to bind
/// to the campus IPv4 address. This ensures the traffic goes over IPv4
/// and is not routed via IPv6 (which may be unfiltered).
///
/// Returns `Ipv4InternetStatus::Reachable` if any check URL succeeds,
/// `CaptivePortal` if a portal redirect is detected,
/// `Unreachable` if all checks fail.
pub async fn check_ipv4_reachability(campus_ipv4: Option<&str>) -> Ipv4InternetStatus {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .no_proxy();

    // Force IPv4 by binding to the campus IPv4 address
    if let Some(ip) = campus_ipv4 {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            builder = builder.local_address(std::net::IpAddr::V4(addr));
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to build IPv4 check client: {}", e);
            return Ipv4InternetStatus::Unreachable;
        }
    };

    for check in REACHABILITY_CHECKS {
        match try_reachability_check(&client, check).await {
            Ok(()) => return Ipv4InternetStatus::Reachable,
            Err(CheckError::CaptivePortal) => return Ipv4InternetStatus::CaptivePortal,
            Err(CheckError::Failed) => continue,
        }
    }

    Ipv4InternetStatus::Unreachable
}

enum CheckError {
    CaptivePortal,
    Failed,
}

async fn try_reachability_check(
    client: &reqwest::Client,
    check: &ReachabilityCheck,
) -> Result<(), CheckError> {
    let resp = client
        .get(check.url)
        .send()
        .await
        .map_err(|e| {
            tracing::debug!("IPv4 check {} failed: {}", check.url, e);
            CheckError::Failed
        })?;

    let status = resp.status();

    if status.is_redirection() {
        if let Some(location) = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            if is_portal_url(location) {
                return Err(CheckError::CaptivePortal);
            }
        }
    }

    match check.success {
        SuccessCondition::Status(expected) => {
            if status.as_u16() == expected {
                Ok(())
            } else {
                Err(CheckError::Failed)
            }
        }
        SuccessCondition::Status204 => {
            if status.as_u16() == 204 {
                Ok(())
            } else {
                Err(CheckError::Failed)
            }
        }
        SuccessCondition::Status200MinLen(min_len) => {
            if !status.is_success() {
                return Err(CheckError::Failed);
            }
            if min_len == 0 {
                return Ok(());
            }
            let body = resp.bytes().await.map_err(|_| CheckError::Failed)?;
            if body.len() >= min_len {
                Ok(())
            } else {
                tracing::debug!("{} body too short: {} < {}", check.url, body.len(), min_len);
                Err(CheckError::Failed)
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
