use std::net::IpAddr;

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
    ipv4_by_if_name(if_name, &ifaces)
}

pub fn ipv4_by_if_name(if_name: &str, ifaces: &[(String, IpAddr)]) -> Option<String> {
    ipv4_by_if_name_preferring(if_name, ifaces, None)
}

pub fn ipv4_by_if_name_preferring(
    if_name: &str,
    ifaces: &[(String, IpAddr)],
    preferred_ip: Option<&str>,
) -> Option<String> {
    if if_name.is_empty() {
        return None;
    }
    let v4: Vec<&(String, IpAddr)> = ifaces.iter().filter(|(_, ip)| ip.is_ipv4()).collect();

    // Prefer an exact adapter name; partial names remain supported for old configs.
    let exact_matches: Vec<&(String, IpAddr)> = v4
        .iter()
        .copied()
        .filter(|(name, _)| name == if_name)
        .collect();
    let candidates = if exact_matches.is_empty() {
        v4.iter()
            .copied()
            .filter(|(name, _)| name.contains(if_name))
            .collect()
    } else {
        exact_matches
    };

    let Some((name, first_ip)) = candidates.first().copied() else {
        tracing::warn!(
            "[IP] if_name '{}' not found. Available IPv4 interfaces: {:?}",
            if_name,
            v4.iter()
                .map(|(n, a)| format!("{}={}", n, a))
                .collect::<Vec<_>>()
        );
        return None;
    };
    // Multiple addresses on one adapter are valid; multiple adapter names are not.
    if candidates.iter().any(|(candidate, _)| candidate != name) {
        let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
        tracing::warn!(
            "[IP] if_name '{}' is ambiguous, contains matches: {:?}. Cannot select one.",
            if_name,
            names
        );
        return None;
    }

    let ip = preferred_ip
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .and_then(|preferred| candidates.iter().copied().find(|(_, ip)| *ip == preferred))
        .map(|(_, ip)| ip)
        .unwrap_or(first_ip);
    tracing::debug!("[IP] if_name '{}' matched by '{}' → {}", if_name, name, ip);
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_names_are_ambiguous_only_for_distinct_interfaces() {
        let mut interfaces = vec![
            ("test-campus adapter".into(), "10.0.0.3".parse().unwrap()),
            ("test-campus adapter".into(), "10.0.0.2".parse().unwrap()),
        ];
        assert_eq!(
            ipv4_by_if_name("test-campus", &interfaces).as_deref(),
            Some("10.0.0.3")
        );
        interfaces.push(("test-campus spare".into(), "10.0.0.4".parse().unwrap()));
        assert!(ipv4_by_if_name("test-campus", &interfaces).is_none());
        assert_eq!(
            ipv4_by_if_name("test-campus adapter", &interfaces).as_deref(),
            Some("10.0.0.3")
        );
    }
}
