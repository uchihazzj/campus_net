use egui::RichText;

use super::presentation::{
    binding_hint, card_frame, deletion_is_current, format_duration, tone_color, Tone,
};

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
        self.edit_error = false;
        self.refresh_edit_network_cache();
        self.show_add_dialog = true;
    }

    fn open_edit_dialog(&mut self, user_idx: usize) {
        let user = self
            .state
            .lock()
            .unwrap()
            .config
            .users
            .get(user_idx)
            .cloned();
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
            self.edit_error = false;
        }
    }

    fn render_user_card(&mut self, ui: &mut egui::Ui, user_idx: usize) {
        let t = self.t();
        let (user, status, auth_busy, confirmed_info, session_known, switching) = {
            let s = self.state.lock().unwrap();
            let (Some(user), Some(status)) =
                (s.config.users.get(user_idx), s.user_statuses.get(user_idx))
            else {
                return;
            };
            (
                user.clone(),
                status.clone(),
                s.authentication_busy(),
                s.confirmed_user_info(user_idx).cloned(),
                s.definitely_offline() || s.current_online_info().is_some(),
                auth::login_will_switch_account(&s, user_idx),
            )
        };
        let login_hint = if switching {
            format!("{}\n{}", t.login_switch_hint, t.login_recovery_hint)
        } else {
            t.login_recovery_hint.to_string()
        };
        let card = if confirmed_info.is_some() {
            card_frame(ui).stroke(egui::Stroke::new(
                1.0,
                tone_color(ui, Tone::Positive).gamma_multiply(0.45),
            ))
        } else {
            card_frame(ui)
        };
        card.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled_ui(!auth_busy, |ui| {
                        ui.menu_button(t.btn_more, |ui| {
                            if ui.button(t.btn_edit).on_hover_text(t.hint_edit).clicked() {
                                self.open_edit_dialog(user_idx);
                                ui.close_menu();
                            }
                            if ui
                                .button(
                                    RichText::new(t.btn_delete).color(tone_color(ui, Tone::Error)),
                                )
                                .on_hover_text(t.hint_delete)
                                .clicked()
                            {
                                self.pending_delete = Some((user_idx, user.clone()));
                                ui.close_menu();
                            }
                        });
                    });
                    if should_show_logout_button(&status.state) {
                        if ui
                            .add_enabled(!auth_busy, egui::Button::new(t.btn_logout))
                            .clicked()
                        {
                            auth::spawn_logout(self.state.clone(), user_idx);
                        }
                    } else if ui
                        .add_enabled(
                            !auth_busy,
                            egui::Button::new(if switching {
                                t.btn_switch_login
                            } else {
                                t.btn_login
                            }),
                        )
                        .on_hover_text(&login_hint)
                        .clicked()
                    {
                        auth::spawn_login(self.state.clone(), user_idx);
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&user.username).size(16.0).strong())
                                .truncate(),
                        )
                        .on_hover_text(&user.username);
                    });
                });
            });
            let (status_text, tone, hint) = match status.state {
                LoginState::Online if confirmed_info.is_some() => {
                    (t.status_online, Tone::Positive, t.campus_auth_confirmed)
                }
                LoginState::Online => (
                    t.status_last_online,
                    Tone::Warning,
                    t.online_info_stale_hint,
                ),
                LoginState::PendingConfirm => {
                    (t.status_pending_confirm, Tone::Warning, t.pending_hint)
                }
                LoginState::LoggingIn => (t.status_logging_in, Tone::Warning, t.auth_busy_hint),
                LoginState::LoggingOut => (t.status_logging_out, Tone::Warning, t.auth_busy_hint),
                LoginState::LoggedOut if session_known => {
                    (t.status_offline, Tone::Muted, t.one_click_login_hint)
                }
                LoginState::LoggedOut => (t.campus_auth_unknown, Tone::Muted, t.unknown_hint),
                LoginState::Error => (t.status_error, Tone::Error, status.last_error.as_str()),
            };
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(tone_color(ui, tone), format!("●  {}", status_text))
                    .on_hover_text(hint);
                ui.small(binding_hint(&user, &t));
            });
            if let Some(info) = confirmed_info {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("{} {}", t.ip_label, info.online_ip));
                    ui.label(format!(
                        "{} {}",
                        t.online_duration_label,
                        format_duration(info.sum_seconds)
                    ))
                    .on_hover_text(t.duration_hint);
                    if info.remain_bytes > 0 {
                        ui.label(format!(
                            "{} {}",
                            t.remain_traffic_label,
                            crate::ui::format_bytes(info.remain_bytes)
                        ));
                    }
                });
                if !info.products_name.is_empty() {
                    ui.weak(format!("{} {}", t.plan_label, info.products_name));
                }
            } else if !status.current_ip.is_empty() {
                ui.label(format!("{} {}", t.last_ip_label, status.current_ip));
            }
            if user.if_name.as_deref().is_some_and(|name| !name.is_empty()) {
                if let Some(ip) = user.ip.as_deref().filter(|ip| !ip.is_empty()) {
                    ui.weak(format!("{} {}", t.fallback_ip_label, ip));
                }
            }
            if !status.last_error.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("{}: {}", t.status_error, status.last_error))
                            .color(tone_color(ui, Tone::Error)),
                    )
                    .truncate(),
                )
                .on_hover_text(&status.last_error);
            }
        });
    }

    pub(super) fn render_user_list(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let (user_count, busy, preserve_session, can_logout) = {
            let s = self.state.lock().unwrap();
            (
                s.config.users.len(),
                s.authentication_busy(),
                s.current_online_info().is_some()
                    || (!s.definitely_offline()
                        && s.user_statuses
                            .iter()
                            .any(|u| u.state == LoginState::PendingConfirm)),
                s.user_statuses
                    .iter()
                    .any(|u| should_show_logout_button(&u.state)),
            )
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("{} · {}", t.section_accounts, user_count))
                    .size(16.0)
                    .strong(),
            );
            if ui
                .add_enabled(!busy, egui::Button::new(t.btn_add_user))
                .clicked()
            {
                self.open_add_dialog();
            }
        });
        if user_count == 0 {
            ui.weak(t.no_users_hint);
        } else {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !busy && !preserve_session,
                        egui::Button::new(t.btn_login_all).fill(ui.visuals().selection.bg_fill),
                    )
                    .on_hover_text(format!(
                        "{}\n{}",
                        t.one_click_login_hint, t.login_recovery_hint
                    ))
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_login(state).await });
                }
                if ui
                    .add_enabled(!busy && can_logout, egui::Button::new(t.btn_logout_all))
                    .on_hover_text(t.one_click_logout_hint)
                    .clicked()
                {
                    let state = self.state.clone();
                    tokio::spawn(async move { auth::do_one_click_logout(state).await });
                }
            });
            for idx in 0..user_count {
                self.render_user_card(ui, idx);
                ui.add_space(3.0);
            }
        }
    }

    pub(super) fn render_delete_dialog(&mut self, ctx: &egui::Context) {
        let Some((idx, expected)) = self.pending_delete.clone() else {
            return;
        };
        let t = self.t();
        let mut open = true;
        let mut cancel = false;
        let mut confirm = false;
        let (can_delete, busy) = {
            let s = self.state.lock().unwrap();
            (
                deletion_is_current(&s, idx, &expected),
                s.authentication_busy(),
            )
        };
        egui::Window::new(t.delete_title)
            .id(egui::Id::new("delete_account"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width((ctx.screen_rect().width() - 48.0).clamp(200.0, 380.0))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(RichText::new(&expected.username).strong());
                ui.label(t.delete_hint);
                ui.horizontal_wrapped(|ui| {
                    cancel = ui.button(t.btn_cancel).clicked();
                    confirm = ui
                        .add_enabled(can_delete, egui::Button::new(t.btn_delete))
                        .clicked();
                });
                if !can_delete {
                    ui.weak(if busy {
                        t.auth_busy_hint
                    } else {
                        t.account_changed_hint
                    });
                }
            });
        if confirm {
            let removed = {
                let mut s = self.state.lock().unwrap();
                if deletion_is_current(&s, idx, &expected) {
                    let removed = s.remove_user(idx);
                    if removed {
                        s.add_log("[INFO] Removed user".into());
                    }
                    removed
                } else {
                    false
                }
            };
            if removed {
                if let Some(edit_idx) = self.editing_user_idx {
                    if edit_idx == idx {
                        self.editing_user_idx = None;
                        self.show_add_dialog = false;
                    } else if edit_idx > idx {
                        self.editing_user_idx = Some(edit_idx - 1);
                    }
                }
                self.save_config();
                self.pending_delete = None;
                ctx.request_repaint();
            }
        }
        if cancel || !open || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.pending_delete = None;
        }
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
