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
    get_network_interfaces()
        .iter()
        .find(|(name, ip)| name.contains(if_name) && ip.is_ipv4())
        .map(|(_, ip)| ip.to_string())
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
