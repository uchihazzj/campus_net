use std::net::Ipv4Addr;
use std::time::Duration;

/// Build a `reqwest::Client` with the common settings used by campus-network
/// probe functions.
///
/// Always applies:
/// - `redirect(Policy::none())`
/// - `no_brotli()`, `no_gzip()`, `no_deflate()`, `no_proxy()`
///
/// Callers provide their own `connect_timeout` and `request_timeout`.
/// If `campus_ipv4` is Some and parses as an IPv4 address, the client's
/// local socket is bound to that address.
///
/// Returns `(client, bound)` where `bound` is true when the local-address
/// binding was successfully applied.
pub fn build_probe_client(
    connect_timeout: Duration,
    request_timeout: Duration,
    campus_ipv4: Option<&str>,
) -> Result<(reqwest::Client, bool), String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
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

    let client = builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    Ok((client, bound))
}
