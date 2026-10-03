use egui::{Color32, RichText};

use super::CampusNetApp;
use crate::core::utils::get_network_interfaces;
use crate::service::{auth, LoginState};

impl CampusNetApp {
    pub(super) fn refresh_edit_network_cache(&mut self) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.edit_network_rx = Some(rx);
        self.edit_interfaces.clear();
        self.edit_detected_ip = None;
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(get_network_interfaces());
            crate::service::request_ui_repaint();
        });
    }

    pub(super) fn poll_edit_network_cache(&mut self) {
        let Some(rx) = &self.edit_network_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(interfaces) => {
                let candidates =
                    crate::service::detection::campus_ip_candidates_from_interfaces(&interfaces);
                self.edit_detected_ip = candidates.first().map(|(_, ip)| ip.clone());
                if self.show_add_dialog && self.edit_if_name.is_empty() {
                    if let Some((name, _)) = candidates.first() {
                        self.edit_if_name = name.clone();
                    }
                }
                self.edit_interfaces = interfaces;
                self.edit_network_rx = None;
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => self.edit_network_rx = None,
            Err(crossbeam_channel::TryRecvError::Empty) => {}
        }
    }

    pub(super) fn open_add_dialog(&mut self) {
        self.editing_user_idx = None;
        self.edit_username.clear();
        self.edit_password.clear();
        self.edit_ip.clear();
        self.edit_if_name.clear();
        self.edit_original_username.clear();
        self.edit_original_ip.clear();
        self.edit_original_if_name.clear();
        self.refresh_edit_network_cache();
        self.show_add_dialog = true;
    }

    fn render_user_card(&mut self, ui: &mut egui::Ui, user_idx: usize) {
        let t = self.t();
        let (username, state, current_ip, last_error, auth_busy) = {
            let s = self.state.lock().unwrap();
            let Some(user) = s.config.users.get(user_idx) else {
                return;
            };
            let Some(us) = s.user_statuses.get(user_idx) else {
                return;
            };
            (
                user.username.clone(),
                us.state.clone(),
                us.current_ip.clone(),
                us.last_error.clone(),
                s.authentication_busy(),
            )
        };

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                match &state {
                    LoginState::Online => {
                        ui.colored_label(Color32::GREEN, "●");
                        ui.label(RichText::new(t.status_online).color(Color32::GREEN));
                        let (confirmed, stale) = {
                            let s = self.state.lock().unwrap();
                            let c = s
                                .online_info
                                .as_ref()
                                .map(|info| {
                                    crate::service::online_info::match_account(
                                        &info.user_name,
                                        &s.config.users,
                                    )
                                })
                                .map(|mr| match mr {
                                    crate::service::online_info::MatchResult::Exact(i)
                                    | crate::service::online_info::MatchResult::UniqueBase(i) => {
                                        i == user_idx
                                    }
                                    _ => false,
                                })
                                .unwrap_or(false);
                            (c, s.online_info_stale)
                        };
                        if confirmed {
                            ui.colored_label(Color32::GREEN, t.campus_auth_confirmed);
                            if stale {
                                ui.colored_label(Color32::GRAY, t.online_info_stale_hint);
                            }
                        }
                    }
                    LoginState::PendingConfirm => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_pending_confirm).color(Color32::YELLOW));
                        let stale = {
                            let s = self.state.lock().unwrap();
                            s.online_info_stale
                        };
                        if stale {
                            ui.colored_label(Color32::GRAY, t.online_info_stale_hint);
                        }
                    }
                    LoginState::LoggingIn => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_logging_in).color(Color32::YELLOW));
                    }
                    LoginState::LoggingOut => {
                        ui.colored_label(Color32::YELLOW, "◐");
                        ui.label(RichText::new(t.status_logging_out).color(Color32::YELLOW));
                    }
                    LoginState::LoggedOut => {
                        ui.colored_label(Color32::GRAY, "○");
                        ui.label(t.status_offline);
                    }
                    LoginState::Error => {
                        ui.colored_label(Color32::RED, "⬤");
                        ui.label(RichText::new(t.status_error).color(Color32::RED));
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!auth_busy, egui::Button::new(t.btn_delete))
                        .on_hover_text(t.hint_delete)
                        .clicked()
                    {
                        {
                            let mut s = self.state.lock().unwrap();
                            if !s.remove_user(user_idx) {
                                return;
                            }
                            s.add_log("[INFO] Removed user".to_string());
                        }
                        if let Some(edit_idx) = self.editing_user_idx {
                            if edit_idx == user_idx {
                                self.editing_user_idx = None;
                                self.show_add_dialog = false;
                            } else if edit_idx > user_idx {
                                self.editing_user_idx = Some(edit_idx - 1);
                            }
                        }
                        self.save_config();
                        return;
                    }

                    if ui
                        .add_enabled(!auth_busy, egui::Button::new(t.btn_edit))
                        .on_hover_text(t.hint_edit)
                        .clicked()
                    {
                        let user = {
                            let s = self.state.lock().unwrap();
                            s.config.users.get(user_idx).cloned()
                        };
                        if let Some(user) = user {
                            self.refresh_edit_network_cache();
                            self.editing_user_idx = Some(user_idx);
                            self.edit_username = user.username.clone();
                            self.edit_password.clear();
                            self.edit_ip = user.ip.clone().unwrap_or_default();
                            self.edit_if_name = user.if_name.clone().unwrap_or_default();
                            self.edit_original_username = user.username;
                            self.edit_original_ip = user.ip.unwrap_or_default();
                            self.edit_original_if_name = user.if_name.unwrap_or_default();
                            self.show_add_dialog = false;
                        }
                    }

                    let is_busy = auth_busy;

                    if should_show_logout_button(&state) {
                        if ui
                            .add_enabled(!is_busy, egui::Button::new(t.btn_logout))
                            .clicked()
                        {
                            auth::spawn_logout(self.state.clone(), user_idx);
                        }
                    } else if ui
                        .add_enabled(!is_busy, egui::Button::new(t.btn_login))
                        .clicked()
                    {
                        auth::spawn_login(self.state.clone(), user_idx);
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.label(t.user_label);
                ui.label(RichText::new(&username).strong());
            });

            let confirmed_info = {
                let s = self.state.lock().unwrap();
                s.online_info
                    .as_ref()
                    .filter(|info| {
                        let mr = crate::service::online_info::match_account(
                            &info.user_name,
                            &s.config.users,
                        );
                        matches!(
                            mr,
                            crate::service::online_info::MatchResult::Exact(i)
                                | crate::service::online_info::MatchResult::UniqueBase(i)
                                if i == user_idx
                        )
                    })
                    .cloned()
            };

            if let Some(ref info) = confirmed_info {
                ui.label(format!("{} {}", t.ip_label, info.online_ip));

                let hours = info.sum_seconds / 3600;
                ui.label(format!("{} {}h", t.online_duration_label, hours));

                if info.remain_bytes > 0 {
                    ui.label(format!(
                        "{} {}",
                        t.remain_traffic_label,
                        crate::ui::format_bytes(info.remain_bytes)
                    ));
                }

                if !info.products_name.is_empty() {
                    ui.colored_label(
                        Color32::GRAY,
                        format!("{} {}", t.plan_label, info.products_name),
                    );
                }
            } else if !current_ip.is_empty() {
                ui.label(format!("{} {}", t.ip_label, current_ip));
            } else {
                let s = self.state.lock().unwrap();
                if let Some(user) = s.config.users.get(user_idx) {
                    if let Some(ref ip) = user.ip {
                        if !ip.is_empty() {
                            ui.label(format!(
                                "{} {}",
                                t.ip_label,
                                t.ip_configured.replace("{}", ip)
                            ));
                        } else if let Some(ref if_name) = user.if_name {
                            ui.label(t.ip_interface.replace("{}", if_name));
                        } else {
                            ui.label(t.ip_auto_detect);
                        }
                    } else if let Some(ref if_name) = user.if_name {
                        ui.label(t.ip_interface.replace("{}", if_name));
                    } else {
                        ui.label(t.ip_auto_detect);
                    }
                }
            }

            if let LoginState::Error = &state {
                if !last_error.is_empty() {
                    ui.colored_label(Color32::RED, format!("Error: {}", last_error));
                }
            }
        });
    }

    pub(super) fn render_user_list(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let user_count = {
            let s = self.state.lock().unwrap();
            s.config.users.len()
        };

        if user_count == 0 {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(t.no_users_hint);
                ui.add_space(20.0);
            });
        } else {
            for idx in 0..user_count {
                self.render_user_card(ui, idx);
                ui.add_space(4.0);
            }
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button(t.btn_add_user).clicked() {
                self.open_add_dialog();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let any_busy = {
                    let s = self.state.lock().unwrap();
                    s.authentication_busy()
                };

                if ui
                    .add_enabled(!any_busy, egui::Button::new(t.btn_login_all))
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_login(state).await });
                }
                if ui
                    .add_enabled(!any_busy, egui::Button::new(t.btn_logout_all))
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_logout(state).await });
                }
            });
        });
    }
}

fn should_show_logout_button(state: &LoginState) -> bool {
    matches!(state, LoginState::Online | LoginState::PendingConfirm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_button_for_online() {
        assert!(should_show_logout_button(&LoginState::Online));
    }

    #[test]
    fn logout_button_for_pending_confirm() {
        assert!(should_show_logout_button(&LoginState::PendingConfirm));
    }

    #[test]
    fn login_button_for_error() {
        assert!(!should_show_logout_button(&LoginState::Error));
    }

    #[test]
    fn login_button_for_logged_out() {
        assert!(!should_show_logout_button(&LoginState::LoggedOut));
    }

    #[test]
    fn busy_button_for_logging_in() {
        assert!(!should_show_logout_button(&LoginState::LoggingIn));
    }

    #[test]
    fn busy_button_for_logging_out() {
        assert!(!should_show_logout_button(&LoginState::LoggingOut));
    }
}
