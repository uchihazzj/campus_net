use egui::Color32;

use super::CampusNetApp;
use crate::platform::secure_store;
use crate::service::config::StoredUser;

impl CampusNetApp {
    pub(super) fn render_edit_dialog(&mut self, ctx: &egui::Context) {
        let t = self.t();
        let show = self.show_add_dialog || self.editing_user_idx.is_some();
        if !show {
            return;
        }

        let is_new_user = self.show_add_dialog;
        let title = if is_new_user {
            t.edit_title_add
        } else {
            t.edit_title_edit
        };

        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(t.field_username);
                ui.text_edit_singleline(&mut self.edit_username);

                ui.label(t.field_password);
                let pwd_hint = if is_new_user {
                    t.field_password_hint
                } else {
                    t.field_password_hint_edit
                };
                ui.add(
                    egui::TextEdit::singleline(&mut self.edit_password)
                        .password(true)
                        .hint_text(pwd_hint),
                );

                ui.label(t.field_ip);
                ui.text_edit_singleline(&mut self.edit_ip)
                    .on_hover_text(t.field_ip_hint);

                if let Some(ref dip) = self.edit_detected_ip {
                    ui.colored_label(Color32::GRAY, t.ip_detected.replace("{}", dip));
                }

                ui.label(t.field_if_name);
                ui.text_edit_singleline(&mut self.edit_if_name)
                    .on_hover_text(t.field_if_name_hint);

                if !self.edit_interfaces.is_empty() {
                    ui.label(t.available_interfaces);
                    for (name, ip) in &self.edit_interfaces {
                        if ui.button(format!("  {} — {}", name, ip)).clicked() {
                            self.edit_if_name.clone_from(name);
                        }
                    }
                } else {
                    ui.colored_label(Color32::YELLOW, "No network interfaces detected");
                }

                ui.add_space(8.0);

                let can_save = if is_new_user {
                    !self.edit_username.is_empty() && !self.edit_password.is_empty()
                } else {
                    !self.edit_username.is_empty()
                        && (self.edit_username != self.edit_original_username
                            || !self.edit_password.is_empty()
                            || self.edit_ip != self.edit_original_ip
                            || self.edit_if_name != self.edit_original_if_name)
                };

                ui.horizontal(|ui| {
                    if ui.button(t.btn_cancel).clicked() {
                        self.show_add_dialog = false;
                        self.editing_user_idx = None;
                    }

                    let save_btn = egui::Button::new(t.btn_save);
                    if ui.add_enabled(can_save, save_btn).clicked() {
                        let encrypted = if self.edit_password.is_empty() {
                            if let Some(idx) = self.editing_user_idx {
                                let s = self.state.lock().unwrap();
                                s.config
                                    .users
                                    .get(idx)
                                    .map(|u| u.encrypted_password.clone())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            }
                        } else {
                            secure_store::encrypt_password(&self.edit_password)
                                .unwrap_or_else(|_| String::new())
                        };

                        let new_user = StoredUser {
                            username: self.edit_username.clone(),
                            encrypted_password: encrypted,
                            ip: if self.edit_ip.is_empty() {
                                None
                            } else {
                                Some(self.edit_ip.clone())
                            },
                            if_name: if self.edit_if_name.is_empty() {
                                None
                            } else {
                                Some(self.edit_if_name.clone())
                            },
                        };

                        {
                            let mut s = self.state.lock().unwrap();
                            if let Some(idx) = self.editing_user_idx {
                                if idx < s.config.users.len() {
                                    s.config.users[idx] = new_user;
                                    let uname = s.config.users[idx].username.clone();
                                    s.add_log(format!("[INFO] Updated user {}", uname));
                                }
                            } else {
                                s.config.users.push(new_user);
                                s.user_statuses.push(crate::service::UserStatus::new());
                                let uname = s.config.users.last().unwrap().username.clone();
                                s.add_log(format!("[INFO] Added user {}", uname));
                            }
                            s.ensure_statuses();
                        }

                        self.save_config();
                        self.show_add_dialog = false;
                        self.editing_user_idx = None;
                    }
                });

                if !can_save {
                    ui.add_space(4.0);
                    if is_new_user {
                        ui.colored_label(Color32::GRAY, "Username and password are required");
                    } else if self.edit_username.is_empty() {
                        ui.colored_label(Color32::GRAY, "Username is required");
                    } else {
                        ui.colored_label(Color32::GRAY, "No changes detected");
                    }
                }
            });
    }
}
