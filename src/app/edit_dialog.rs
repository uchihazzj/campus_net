use egui::RichText;

use super::presentation::{tone_color, valid_optional_ipv4, Tone};
use super::CampusNetApp;
use crate::platform::secure_store;
use crate::service::config::StoredUser;

impl CampusNetApp {
    fn close_edit_dialog(&mut self) {
        self.show_add_dialog = false;
        self.editing_user_idx = None;
        self.edit_password.clear();
        self.edit_error = false;
        self.edit_network_rx = None;
    }

    fn save_edited_user(&mut self) -> bool {
        let encrypted = if self.edit_password.is_empty() {
            let s = self.state.lock().unwrap();
            let Some(user) = self
                .editing_user_idx
                .and_then(|idx| s.config.users.get(idx))
            else {
                return false;
            };
            user.encrypted_password.clone()
        } else {
            match secure_store::encrypt_password(&self.edit_password) {
                Ok(value) => value,
                Err(_) => {
                    self.state.lock().unwrap().add_log(
                        "[ERROR] Failed to encrypt password; account was not changed".into(),
                    );
                    return false;
                }
            }
        };
        let new_user = StoredUser {
            username: self.edit_username.clone(),
            encrypted_password: encrypted,
            ip: (!self.edit_ip.is_empty()).then(|| self.edit_ip.clone()),
            if_name: (!self.edit_if_name.is_empty()).then(|| self.edit_if_name.clone()),
        };
        {
            let mut s = self.state.lock().unwrap();
            if s.authentication_busy() {
                return false;
            }
            if let Some(idx) = self.editing_user_idx {
                if s.config
                    .users
                    .get(idx)
                    .is_none_or(|user| user.username != self.edit_original_username)
                {
                    return false;
                }
                s.replace_user(idx, new_user);
                s.add_log("[INFO] Updated user".into());
            } else {
                s.config.users.push(new_user);
                s.user_statuses.push(crate::service::UserStatus::new());
                s.invalidate_auth_context();
                s.add_log("[INFO] Added user".into());
            }
            s.ensure_statuses();
        }
        self.save_config();
        true
    }

    pub(super) fn render_edit_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_add_dialog && self.editing_user_idx.is_none() {
            return;
        }
        let t = self.t();
        let is_new = self.show_add_dialog;
        let title = if is_new {
            t.edit_title_add
        } else {
            t.edit_title_edit
        };
        let mut open = true;
        let mut cancel = false;
        let mut save = false;
        let auth_busy = self.state.lock().unwrap().authentication_busy();
        egui::Window::new(title)
            .id(egui::Id::new("account_edit"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width((ctx.screen_rect().width() - 48.0).clamp(200.0, 400.0))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("account_form")
                    .max_height((ctx.screen_rect().height() - 165.0).max(70.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.label(t.field_username);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_username)
                                .desired_width(ui.available_width()),
                        );
                        ui.label(t.field_password);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_password)
                                .password(true)
                                .desired_width(ui.available_width())
                                .hint_text(if is_new {
                                    t.field_password_hint
                                } else {
                                    t.field_password_hint_edit
                                }),
                        );
                        ui.label(t.field_if_name);
                        let mut names: Vec<&str> = self
                            .edit_interfaces
                            .iter()
                            .filter(|(_, ip)| ip.is_ipv4())
                            .map(|(name, _)| name.as_str())
                            .collect();
                        names.sort_unstable();
                        names.dedup();
                        egui::ComboBox::from_id_salt("interface_picker")
                            .width(ui.available_width())
                            .selected_text(if self.edit_if_name.is_empty() {
                                t.ip_auto_detect
                            } else {
                                &self.edit_if_name
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.edit_if_name,
                                    String::new(),
                                    t.ip_auto_detect,
                                );
                                for name in names {
                                    let ips = self
                                        .edit_interfaces
                                        .iter()
                                        .filter(|(candidate, ip)| candidate == name && ip.is_ipv4())
                                        .map(|(_, ip)| ip.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    ui.selectable_value(
                                        &mut self.edit_if_name,
                                        name.into(),
                                        format!("{} · {}", name, ips),
                                    );
                                }
                            });
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_if_name)
                                .desired_width(ui.available_width())
                                .hint_text(t.field_if_name_hint),
                        )
                        .on_hover_text(t.field_if_name_hint);
                        if self.edit_network_rx.is_some() {
                            ui.spinner();
                        } else if self.edit_interfaces.is_empty() {
                            ui.weak(t.no_interfaces);
                        }
                        egui::CollapsingHeader::new(t.section_advanced)
                            .id_salt("account_advanced")
                            .default_open(!self.edit_ip.is_empty())
                            .show(ui, |ui| {
                                ui.label(t.field_ip);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.edit_ip)
                                        .desired_width(ui.available_width()),
                                )
                                .on_hover_text(t.field_ip_hint);
                                ui.weak(t.field_ip_hint);
                                if let Some(ip) = &self.edit_detected_ip {
                                    ui.small(t.ip_detected.replace("{}", ip));
                                }
                            });
                    });
                ui.separator();
                let changed = is_new
                    || self.edit_username != self.edit_original_username
                    || !self.edit_password.is_empty()
                    || self.edit_ip != self.edit_original_ip
                    || self.edit_if_name != self.edit_original_if_name;
                let reason = if auth_busy {
                    Some(t.auth_busy_hint)
                } else if self.edit_username.trim().is_empty()
                    || (is_new && self.edit_password.is_empty())
                {
                    Some(if is_new {
                        t.credentials_required
                    } else {
                        t.username_required
                    })
                } else if !valid_optional_ipv4(&self.edit_ip) {
                    Some(t.invalid_ipv4_hint)
                } else if !changed {
                    Some(t.no_changes)
                } else {
                    None
                };
                ui.horizontal_wrapped(|ui| {
                    save = ui
                        .add_enabled(
                            reason.is_none(),
                            egui::Button::new(RichText::new(t.btn_save).strong()),
                        )
                        .clicked();
                    cancel = ui.button(t.btn_cancel).clicked();
                });
                if let Some(reason) = reason {
                    ui.small(reason);
                }
                if self.edit_error {
                    ui.colored_label(tone_color(ui, Tone::Error), t.save_failed_hint);
                }
            });
        if save {
            if self.save_edited_user() {
                self.close_edit_dialog();
            } else {
                self.edit_error = true;
            }
        }
        if cancel || !open || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.close_edit_dialog();
        }
    }
}
