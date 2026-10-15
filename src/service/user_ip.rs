use crate::core::utils::{get_network_interfaces, ipv4_by_if_name};
use crate::service::config::StoredUser;
use crate::service::detection::detect_campus_ip_from_interfaces;
use crate::service::UserStatus;

fn non_empty(value: &str) -> bool {
    !value.is_empty()
}

pub fn configured_static_ip(user: &StoredUser) -> Option<String> {
    user.ip.as_ref().filter(|ip| non_empty(ip)).cloned()
}

pub fn resolve_login_ip(user: &StoredUser) -> String {
    // A static-only account needs no interface enumeration. Otherwise take
    // one fresh snapshot for both its binding and the auto-detection fallback.
    if user.if_name.as_deref().is_none_or(str::is_empty) {
        if let Some(ip) = configured_static_ip(user) {
            return ip;
        }
    }
    resolve_login_ip_from_interfaces(user, &get_network_interfaces())
}

fn resolve_login_ip_from_interfaces(
    user: &StoredUser,
    interfaces: &[(String, std::net::IpAddr)],
) -> String {
    user.if_name
        .as_ref()
        .and_then(|name| ipv4_by_if_name(name, interfaces))
        .filter(|ip| non_empty(ip))
        .or_else(|| configured_static_ip(user))
        .or_else(|| detect_campus_ip_from_interfaces(interfaces))
        .unwrap_or_default()
}

pub fn resolve_logout_ip(user: &StoredUser, current_ip: &str) -> String {
    if non_empty(current_ip) {
        current_ip.to_string()
    } else {
        resolve_login_ip(user)
    }
}

pub fn has_usable_user_ip(
    user: Option<&StoredUser>,
    status: Option<&UserStatus>,
    interfaces: &[(String, std::net::IpAddr)],
) -> bool {
    if status.is_some_and(|us| non_empty(&us.current_ip)) {
        return true;
    }

    let Some(user) = user else {
        return false;
    };

    if configured_static_ip(user).is_some() {
        return true;
    }

    user.if_name
        .as_ref()
        .and_then(|name| ipv4_by_if_name(name, interfaces))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(ip: Option<&str>, if_name: Option<&str>) -> StoredUser {
        StoredUser {
            username: "u".to_string(),
            encrypted_password: "p".to_string(),
            ip: ip.map(ToString::to_string),
            if_name: if_name.map(ToString::to_string),
        }
    }

    #[test]
    fn configured_static_ip_ignores_empty_ip() {
        assert_eq!(configured_static_ip(&user(Some(""), None)), None);
        assert_eq!(
            configured_static_ip(&user(Some("10.0.0.2"), None)),
            Some("10.0.0.2".to_string())
        );
    }

    #[test]
    fn logout_ip_prefers_current_session_ip() {
        let user = user(Some("10.0.0.2"), None);
        assert_eq!(resolve_logout_ip(&user, "10.0.0.3"), "10.0.0.3");
    }

    #[test]
    fn usable_ip_accepts_current_status_ip() {
        let status = UserStatus {
            state: crate::service::LoginState::LoggedOut,
            current_ip: "10.0.0.3".to_string(),
            last_error: String::new(),
        };
        assert!(has_usable_user_ip(None, Some(&status), &[]));
    }

    #[test]
    fn usable_ip_accepts_configured_static_ip() {
        let user = user(Some("10.0.0.2"), None);
        assert!(has_usable_user_ip(Some(&user), None, &[]));
    }

    #[test]
    fn binding_and_fallback_use_the_supplied_snapshot() {
        let interfaces = vec![
            ("test-other".into(), "10.0.0.99".parse().unwrap()),
            ("test-campus".into(), "10.0.0.2".parse().unwrap()),
            ("test-tun".into(), "10.0.0.3".parse().unwrap()),
        ];
        let bound = user(Some("10.0.0.8"), Some("test-campus"));
        assert!(has_usable_user_ip(Some(&bound), None, &interfaces));
        assert_eq!(
            resolve_login_ip_from_interfaces(&bound, &interfaces),
            "10.0.0.2"
        );
        assert_eq!(resolve_login_ip_from_interfaces(&bound, &[]), "10.0.0.8");

        let missing = user(None, Some("test-missing"));
        assert!(!has_usable_user_ip(Some(&missing), None, &interfaces));
        assert_eq!(
            resolve_login_ip_from_interfaces(&missing, &interfaces),
            "10.0.0.99"
        );
        assert_eq!(resolve_login_ip_from_interfaces(&missing, &[]), "");
    }

    #[test]
    fn binding_follows_dhcp_changes_and_never_reuses_a_previous_snapshot() {
        let bound = user(None, Some("test-campus"));
        let before = vec![("test-campus".into(), "10.0.0.2".parse().unwrap())];
        let after = vec![("test-campus".into(), "10.0.0.4".parse().unwrap())];
        assert_eq!(
            resolve_login_ip_from_interfaces(&bound, &before),
            "10.0.0.2"
        );
        assert_eq!(resolve_login_ip_from_interfaces(&bound, &after), "10.0.0.4");
        assert!(!has_usable_user_ip(Some(&bound), None, &[]));
    }
}
