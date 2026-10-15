use super::CampusNetApp;
use crate::platform::autostart;
use crate::service::Ipv4InternetStatus;
use crate::ui::l10n::Lang;

fn apply_autostart_edit(s: &mut crate::service::AppState, enabled: bool, edited: bool) {
    if edited {
        s.config.auto_start = enabled;
        s.autostart_busy = true;
    }
}

impl CampusNetApp {
    fn render_server_edit(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let current = self.state.lock().unwrap().config.server.clone();
        if current != self.server_original {
            self.server_original = current.clone();
            self.server_draft = current.clone();
        }
        ui.label(t.server_label);
        ui.add(
            egui::TextEdit::singleline(&mut self.server_draft)
                .desired_width(ui.available_width())
                .hint_text(t.server_hint),
        )
        .on_hover_text(t.server_tooltip);
        let normalized = super::presentation::normalized_server(&self.server_draft);
        let can_apply = normalized.as_ref().is_some_and(|server| server != &current);
        if ui
            .add_enabled(can_apply, egui::Button::new(t.btn_apply))
            .clicked()
        {
            if let Some(server) = normalized.clone() {
                let changed = self.state.lock().unwrap().set_server(server.clone());
                if changed {
                    self.server_original = server.clone();
                    self.server_draft = server;
                    self.save_config();
                }
            }
        }
        if normalized.is_none() {
            ui.weak(t.server_invalid_hint);
        } else {
            ui.small(t.server_apply_hint);
        }
    }

    pub(super) fn render_settings(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        egui::CollapsingHeader::new(t.section_settings)
            .id_salt("general_settings")
            .show(ui, |ui| {
                let auth_busy = self.state.lock().unwrap().authentication_busy();
                ui.add_enabled_ui(!auth_busy, |ui| {
                    let (
                        mut auto_reconnect,
                        mut minimize_to_tray,
                        mut auto_start,
                        mut enable_ipv4_internet_probe,
                        mut detect_ip,
                        mut strict_bind,
                        mut double_stack,
                        mut monitor_interval,
                        mut retry_times,
                        mut retry_delay,
                        mut n,
                        mut utype,
                        mut acid,
                        mut os,
                        mut name,
                    ) = {
                        let s = self.state.lock().unwrap();
                        let c = &s.config;
                        (
                            c.auto_reconnect,
                            c.minimize_to_tray,
                            c.auto_start,
                            c.enable_ipv4_internet_probe,
                            c.detect_ip,
                            c.strict_bind,
                            c.double_stack,
                            c.monitor_interval_secs,
                            c.retry_times,
                            c.retry_delay,
                            c.n,
                            c.utype,
                            c.acid,
                            c.os.clone(),
                            c.name.clone(),
                        )
                    };
                    let mut lang = {
                        let s = self.state.lock().unwrap();
                        s.config.language
                    };

                    let mut changed = false;
                    ui.label(t.section_app_options);
                    changed |= ui
                        .checkbox(&mut auto_reconnect, t.opt_auto_reconnect)
                        .changed();
                    changed |= ui
                        .checkbox(&mut minimize_to_tray, t.opt_minimize_tray)
                        .changed();
                    let autostart_busy = self.state.lock().unwrap().autostart_busy;
                    let as_changed = ui
                        .add_enabled(
                            !autostart_busy,
                            egui::Checkbox::new(&mut auto_start, t.opt_auto_start),
                        )
                        .changed();
                    changed |= as_changed;
                    ui.horizontal_wrapped(|ui| {
                        ui.label(t.label_monitor_interval);
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut monitor_interval)
                                    .range(15..=300)
                                    .suffix(format!(" {}", t.seconds_unit)),
                            )
                            .changed();
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label(t.label_language);
                        for choice in [Lang::Chinese, Lang::English] {
                            changed |= ui
                                .selectable_value(&mut lang, choice, choice.as_str())
                                .changed();
                        }
                    });
                    ui.separator();
                    self.render_server_edit(ui);
                    egui::CollapsingHeader::new(t.section_advanced)
                        .id_salt("advanced_settings")
                        .show(ui, |ui| {
                            ui.label(t.section_network_options);
                            changed |= ui.checkbox(&mut detect_ip, t.opt_detect_ip).changed();
                            changed |= ui
                                .checkbox(&mut strict_bind, t.opt_strict_bind)
                                .on_hover_text(t.opt_strict_bind_hint)
                                .changed();
                            changed |= ui.checkbox(&mut double_stack, t.opt_double_stack).changed();
                            changed |= ui
                                .checkbox(&mut enable_ipv4_internet_probe, t.enable_ipv4_probe)
                                .on_hover_text(t.enable_ipv4_probe_hint)
                                .changed();
                            ui.weak(t.diagnostics_hint);
                            ui.separator();
                            ui.label(t.section_auth_params);
                            egui::Grid::new("auth_parameters")
                                .num_columns(2)
                                .show(ui, |ui| {
                                    for (label, value, upper) in [
                                        (t.label_n, &mut n, 999),
                                        (t.label_type, &mut utype, 99),
                                        (t.label_acid, &mut acid, 999),
                                    ] {
                                        ui.label(label);
                                        changed |= ui
                                            .add(egui::DragValue::new(value).range(1..=upper))
                                            .changed();
                                        ui.end_row();
                                    }
                                });
                            ui.label(t.label_os);
                            changed |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut os)
                                        .desired_width(ui.available_width()),
                                )
                                .changed();
                            ui.label(t.label_name);
                            changed |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut name)
                                        .desired_width(ui.available_width()),
                                )
                                .changed();
                            ui.separator();
                            ui.label(t.section_retry_options);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(t.label_retry_times);
                                changed |= ui
                                    .add(egui::DragValue::new(&mut retry_times).range(1..=99))
                                    .changed();
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.label(t.label_retry_delay);
                                changed |= ui
                                    .add(egui::DragValue::new(&mut retry_delay).range(100..=30000))
                                    .changed();
                            });
                        });
                    if changed {
                        {
                            let mut s = self.state.lock().unwrap();
                            if s.authentication_busy() {
                                return;
                            }
                            s.config.language = lang;
                            s.config.auto_reconnect = auto_reconnect;
                            s.config.minimize_to_tray = minimize_to_tray;
                            apply_autostart_edit(&mut s, auto_start, as_changed);
                            s.config.enable_ipv4_internet_probe = enable_ipv4_internet_probe;
                            if !enable_ipv4_internet_probe {
                                s.ipv4_internet = Ipv4InternetStatus::Disabled;
                            } else if s.ipv4_internet == Ipv4InternetStatus::Disabled {
                                s.ipv4_internet = Ipv4InternetStatus::Checking;
                            }
                            s.config.detect_ip = detect_ip;
                            s.config.strict_bind = strict_bind;
                            s.config.double_stack = double_stack;
                            s.config.monitor_interval_secs = monitor_interval;
                            s.config.retry_times = retry_times;
                            s.config.retry_delay = retry_delay;
                            s.config.n = n;
                            s.config.utype = utype;
                            s.config.acid = acid;
                            s.config.os = os;
                            s.config.name = name;
                            s.invalidate_auth_context();
                        }
                        self.save_config();
                        if as_changed {
                            let state = self.state.clone();
                            tokio::task::spawn_blocking(move || {
                                let result = if auto_start {
                                    autostart::enable_autostart()
                                } else {
                                    autostart::disable_autostart()
                                };
                                if let Err(e) = &result {
                                    tracing::error!("Failed to change autostart: {}", e);
                                }
                                {
                                    let mut s = state.lock().unwrap();
                                    s.autostart_busy = false;
                                    if let Err(e) = result {
                                        s.config.auto_start = !auto_start;
                                        s.add_log(format!(
                                            "[ERROR] Failed to change autostart: {}",
                                            e
                                        ));
                                    }
                                }
                                if let Err(e) = crate::service::config::save_shared_config(
                                    crate::path::config_path(),
                                    &state,
                                ) {
                                    tracing::error!("Failed to save autostart setting: {}", e);
                                }
                                crate::service::request_ui_repaint();
                            });
                        }
                    }
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_settings_do_not_undo_failed_autostart_rollback() {
        let mut s = crate::service::AppState::new(crate::service::config::AppConfig::default());
        let old_ui_snapshot = true;
        s.config.auto_start = false;
        s.autostart_busy = false;
        apply_autostart_edit(&mut s, old_ui_snapshot, false);
        assert!(!s.config.auto_start);
        assert!(!s.autostart_busy);
        apply_autostart_edit(&mut s, true, true);
        assert!(s.config.auto_start);
        assert!(s.autostart_busy);
    }
}
