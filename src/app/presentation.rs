use egui::{Color32, FontId, TextStyle};

use crate::service::config::StoredUser;
use crate::service::{AppState, LoginState};
use crate::ui::l10n::UiText;

#[derive(Debug, PartialEq)]
pub(super) enum ConnectionStatus {
    Online,
    LoggingIn,
    LoggingOut,
    Pending,
    Offline,
    Stale,
    Unknown,
}

/// Presentation only: never changes the authentication or reconnect decision.
pub(super) fn connection_status(s: &AppState) -> ConnectionStatus {
    if s.user_statuses
        .iter()
        .any(|u| u.state == LoginState::LoggingOut)
    {
        ConnectionStatus::LoggingOut
    } else if s
        .user_statuses
        .iter()
        .any(|u| u.state == LoginState::LoggingIn)
    {
        ConnectionStatus::LoggingIn
    } else if s.current_online_info().is_some() {
        ConnectionStatus::Online
    } else if s.definitely_offline() {
        ConnectionStatus::Offline
    } else if s
        .user_statuses
        .iter()
        .any(|u| u.state == LoginState::PendingConfirm)
    {
        ConnectionStatus::Pending
    } else if s.online_info.is_some()
        || s.user_statuses
            .iter()
            .any(|u| u.state == LoginState::Online)
    {
        ConnectionStatus::Stale
    } else {
        ConnectionStatus::Unknown
    }
}

#[derive(Clone, Copy)]
pub(super) enum Tone {
    Positive,
    Warning,
    Error,
    Muted,
}

pub(super) fn tone_color(ui: &egui::Ui, tone: Tone) -> Color32 {
    match (tone, ui.visuals().dark_mode) {
        (Tone::Positive, true) => Color32::from_rgb(111, 214, 163),
        (Tone::Positive, false) => Color32::from_rgb(26, 117, 70),
        (Tone::Warning, true) => Color32::from_rgb(244, 195, 111),
        (Tone::Warning, false) => Color32::from_rgb(143, 88, 8),
        (Tone::Error, _) => ui.visuals().error_fg_color,
        (Tone::Muted, _) => ui.visuals().text_color(),
    }
}

pub(super) fn card_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::group(ui.style())
        .inner_margin(10.0)
        .rounding(8.0)
        .fill(ui.visuals().faint_bg_color)
}

pub(crate) fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.interact_size.y = 28.0;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(12.0));
    style.visuals.window_rounding = 8.0.into();
    style.visuals.menu_rounding = 6.0.into();
    ctx.set_style(style);
}

pub(super) fn binding_hint(user: &StoredUser, t: &UiText) -> String {
    if let Some(name) = user.if_name.as_deref().filter(|name| !name.is_empty()) {
        t.ip_interface.replace("{}", name)
    } else if let Some(ip) = user.ip.as_deref().filter(|ip| !ip.is_empty()) {
        t.ip_configured.replace("{}", ip)
    } else {
        t.ip_auto_detect.into()
    }
}

pub(super) fn format_duration(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

pub(super) fn valid_optional_ipv4(ip: &str) -> bool {
    ip.is_empty() || ip.parse::<std::net::Ipv4Addr>().is_ok()
}

pub(super) fn normalized_server(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    let normalized = crate::core::srun::SrunClient::normalize_server_url(value);
    let url = reqwest::Url::parse(&normalized).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(normalized)
}

pub(super) fn deletion_is_current(s: &AppState, idx: usize, expected: &StoredUser) -> bool {
    !s.authentication_busy() && s.config.users.get(idx) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{config::AppConfig, CampusAuthStatus, OnlineUserInfo};
    use crate::ui::l10n::{get_text, Lang};

    fn user() -> StoredUser {
        StoredUser {
            username: "test-ui-user".into(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.99".into()),
            if_name: Some("test-campus".into()),
        }
    }

    #[test]
    fn an_ip_or_public_internet_does_not_confirm_campus_login() {
        let mut s = AppState::new(AppConfig::default());
        s.campus_ip = Some("10.0.0.2".into());
        s.ipv4_internet = crate::service::Ipv4InternetStatus::Reachable;
        assert_eq!(connection_status(&s), ConnectionStatus::Unknown);
        s.config.users.push(user());
        s.ensure_statuses();
        s.user_statuses[0].state = LoginState::PendingConfirm;
        assert_eq!(connection_status(&s), ConnectionStatus::Pending);
        s.user_statuses[0].state = LoginState::Online;
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.online_info = Some(OnlineUserInfo {
            error: "ok".into(),
            ..Default::default()
        });
        assert_eq!(connection_status(&s), ConnectionStatus::Online);
        s.online_info_stale = true;
        assert_eq!(connection_status(&s), ConnectionStatus::Stale);
        s.campus_auth = CampusAuthStatus::NotLoggedIn;
        assert_eq!(connection_status(&s), ConnectionStatus::Offline);
    }

    #[test]
    fn configured_interface_takes_precedence_in_the_display() {
        let t = get_text(Lang::English);
        let mut u = user();
        assert_eq!(binding_hint(&u, &t), "Interface: test-campus");
        u.if_name = None;
        assert!(binding_hint(&u, &t).contains("10.0.0.99"));
        u.ip = None;
        assert_eq!(binding_hint(&u, &t), t.ip_auto_detect);
    }

    #[test]
    fn duration_keeps_minutes_and_seconds() {
        assert_eq!(format_duration(59), "00:00:59");
        assert_eq!(format_duration(3661), "01:01:01");
        assert_eq!(format_duration(360000), "100:00:00");
    }

    #[test]
    fn edits_validate_addresses_without_network_requests() {
        assert_eq!(
            normalized_server("10.0.0.55").as_deref(),
            Some("http://10.0.0.55")
        );
        assert!(normalized_server("https://auth.example.test:8443/path").is_some());
        assert!(normalized_server("").is_none());
        assert!(normalized_server("http://").is_none());
        assert!(valid_optional_ipv4(""));
        assert!(valid_optional_ipv4("10.0.0.2"));
        assert!(!valid_optional_ipv4("10.0.0.999"));
        assert!(!valid_optional_ipv4("::1"));
    }

    #[test]
    fn deletion_confirmation_rejects_changed_accounts_and_busy_state() {
        let u = user();
        let mut s = AppState::new(AppConfig {
            users: vec![u.clone()],
            ..Default::default()
        });
        assert!(deletion_is_current(&s, 0, &u));
        s.auth_busy = true;
        assert!(!deletion_is_current(&s, 0, &u));
        s.auth_busy = false;
        s.config.users[0].username = "test-replacement".into();
        assert!(!deletion_is_current(&s, 0, &u));
        assert!(!deletion_is_current(&s, 1, &u));
    }
}
