use std::{
    net::{IpAddr, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

pub fn get_network_interfaces() -> Vec<(String, IpAddr)> {
    match if_addrs::get_if_addrs() {
        Ok(ifs) => ifs
            .into_iter()
            .filter(|i| !i.is_loopback())
            .map(|i| {
                let name = i.name.clone();
                let ip = i.ip();
                (name, ip)
            })
            .collect(),
        Err(e) => {
            tracing::warn!("Failed to get network interfaces: {}", e);
            vec![]
        }
    }
}

pub fn get_ip_by_if_name(if_name: &str) -> Option<String> {
    let ifaces = get_network_interfaces();
    let v4: Vec<&(String, IpAddr)> = ifaces.iter().filter(|(_, ip)| ip.is_ipv4()).collect();

    // Prefer exact match
    if let Some((_, ip)) = v4.iter().find(|(name, _)| name == if_name) {
        tracing::info!("[IP] if_name exact match: '{}' → {}", if_name, ip);
        return Some(ip.to_string());
    }

    // Fallback: contains match (for backward compat with partial names)
    let contains_matches: Vec<&&(String, IpAddr)> = v4
        .iter()
        .filter(|(name, _)| name.contains(if_name))
        .collect();

    match contains_matches.len() {
        0 => {
            tracing::warn!(
                "[IP] if_name '{}' not found. Available IPv4 interfaces: {:?}",
                if_name,
                v4.iter()
                    .map(|(n, a)| format!("{}={}", n, a))
                    .collect::<Vec<_>>()
            );
            None
        }
        1 => {
            let (name, ip) = contains_matches[0];
            tracing::info!(
                "[IP] if_name contains match: '{}' matched by '{}' → {}",
                if_name,
                name,
                ip
            );
            Some(ip.to_string())
        }
        _ => {
            let names: Vec<&str> = contains_matches.iter().map(|(n, _)| n.as_str()).collect();
            tracing::warn!(
                "[IP] if_name '{}' is ambiguous, contains matches: {:?}. Cannot select one.",
                if_name,
                names
            );
            None
        }
    }
}

pub async fn tcp_ping(addr: &'static str) -> anyhow::Result<u16> {
    tokio::task::spawn_blocking(move || {
        let sock_addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS resolve failed for {}", addr))?;
        let start = Instant::now();
        TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3))?;
        Ok(start.elapsed().as_millis() as u16)
    })
    .await?
}
