use std::time::Duration;

use crate::core::utils::get_network_interfaces;

// ── Campus IP Detection ─────────────────────────────────────────

pub fn detect_campus_ip() -> Option<String> {
    get_network_interfaces()
        .iter()
        .filter(|(_, ip)| ip.is_ipv4())
        .map(|(_, ip)| ip.to_string())
        .find(|ip| ip.starts_with("10."))
}

// ── Campus Auth Status (via portal redirect detection) ──────────

#[derive(Debug, Clone, PartialEq)]
pub enum CampusAuthStatus {
    LoggedIn,
    NotLoggedIn,
    ServerUnreachable,
    Unknown,
}

/// Check if logged in by sending an HTTP request to an external URL.
/// If the campus gateway redirects to the portal → NotLoggedIn.
/// If the request succeeds → LoggedIn.
pub async fn check_auth_status() -> CampusAuthStatus {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .build()
    {
        Ok(c) => c,
        Err(_) => return CampusAuthStatus::Unknown,
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
                // Redirect to non-portal URL (e.g., baidu redirects to https)
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

// ── Internet Reachability ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReachabilityResult {
    Reachable,
    CaptivePortal,
    Unreachable,
}

struct ReachabilityCheck {
    url: &'static str,
    success: SuccessCondition,
}

enum SuccessCondition {
    /// Exact status code
    Status(u16),
    /// Status 200 + body must be >= N bytes
    Status200MinLen(usize),
    /// Status 204 (No Content) — specific to generate_204 endpoints
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

pub async fn check_internet_reachability() -> ReachabilityResult {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .no_brotli()
        .no_gzip()
        .no_deflate()
        .build()
    {
        Ok(c) => c,
        Err(_) => return ReachabilityResult::Unreachable,
    };

    for check in REACHABILITY_CHECKS {
        match try_reachability_check(&client, check).await {
            Ok(()) => return ReachabilityResult::Reachable,
            Err(CheckError::CaptivePortal) => return ReachabilityResult::CaptivePortal,
            Err(CheckError::Failed) => continue,
        }
    }

    ReachabilityResult::Unreachable
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
        .map_err(|_| CheckError::Failed)?;

    let status = resp.status();

    // Check for captive portal redirects
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
        // Non-portal redirect — could be http→https upgrade, treat as not an error
        // but we need to check the success condition
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
            let body = resp
                .bytes()
                .await
                .map_err(|_| CheckError::Failed)?;
            if body.len() >= min_len {
                Ok(())
            } else {
                tracing::debug!("{} body too short: {} < {}", check.url, body.len(), min_len);
                Err(CheckError::Failed)
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_campus_ip() {
        let ip = detect_campus_ip();
        println!("Campus IP: {:?}", ip);
    }

    #[tokio::test]
    async fn test_check_auth_status() {
        let status = check_auth_status().await;
        println!("Auth status: {:?}", status);
    }

    #[tokio::test]
    async fn test_check_internet_reachability() {
        let result = check_internet_reachability().await;
        println!("Reachability: {:?}", result);
    }
}
