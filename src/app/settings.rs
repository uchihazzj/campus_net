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
                    let (mut sessions_enabled, mut sessions_interval) = {
                        let s = self.state.lock().unwrap();
                        (
                            s.config.enable_online_sessions,
                            s.config.online_sessions_interval_mins,
                        )
                    };
                    let mut sessions_changed = false;
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
                    sessions_changed |= ui
                        .checkbox(&mut sessions_enabled, t.enable_online_sessions)
                        .on_hover_text(t.online_sessions_hint)
                        .changed();
                    ui.add_enabled_ui(sessions_enabled, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(t.online_sessions_interval);
                            sessions_changed |= ui
                                .add(
                                    egui::DragValue::new(&mut sessions_interval)
                                        .range(1..=1440)
                                        .suffix(format!(" {}", t.minutes_unit)),
                                )
                                .changed();
                        });
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
                    if sessions_changed {
                        {
                            let mut s = self.state.lock().unwrap();
                            if s.config.enable_online_sessions != sessions_enabled {
                                s.online_sessions.fill(Default::default());
                            }
                            s.config.enable_online_sessions = sessions_enabled;
                            s.config.online_sessions_interval_mins =
                                sessions_interval.clamp(1, 1440);
                        }
                        self.save_config();
                    }
                });
                ui.separator();
                self.render_diagnostics(ui);
            });
    }

    pub(super) fn render_diagnostics(&mut self, ui: &mut egui::Ui) {
        use crate::service::diagnostics::{
            self, DiagnosticMode, FunctionalPhase, RunStatus, SaveStatus,
        };
        let t = self.t();
        let (diagnostic, can_start, accounts) = {
            let s = self.state.lock().unwrap();
            (
                s.diagnostics.clone(),
                diagnostics::can_start(&s),
                s.config
                    .users
                    .iter()
                    .map(|user| user.username.clone())
                    .collect::<Vec<_>>(),
            )
        };
        ui.strong(t.diagnostic_title);
        let mut mode = diagnostic.mode;
        let mut selected = diagnostic
            .selected_account
            .min(accounts.len().saturating_sub(1));
        ui.add_enabled_ui(!diagnostic.running(), |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(t.diagnostic_mode);
                egui::ComboBox::from_id_salt("diagnostic_mode")
                    .selected_text(if mode == DiagnosticMode::ReadOnly {
                        t.diagnostic_readonly
                    } else {
                        t.diagnostic_functional
                    })
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut mode,
                            DiagnosticMode::ReadOnly,
                            t.diagnostic_readonly,
                        );
                        ui.selectable_value(
                            &mut mode,
                            DiagnosticMode::Functional,
                            t.diagnostic_functional,
                        );
                    });
            });
            if mode == DiagnosticMode::Functional {
                ui.label(t.diagnostic_account);
                egui::ComboBox::from_id_salt("diagnostic_test_account")
                    .selected_text(accounts.get(selected).map(String::as_str).unwrap_or("—"))
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        for (index, username) in accounts.iter().enumerate() {
                            ui.selectable_value(&mut selected, index, username);
                        }
                    });
            }
        });
        if mode != diagnostic.mode || selected != diagnostic.selected_account {
            let mut s = self.state.lock().unwrap();
            if !s.diagnostics.running() {
                s.diagnostics.mode = mode;
                s.diagnostics.selected_account = selected;
            }
        }
        if mode == DiagnosticMode::ReadOnly {
            ui.small(t.diagnostic_scope);
        } else {
            ui.colored_label(ui.visuals().warn_fg_color, t.diagnostic_full_hint);
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    can_start && (mode == DiagnosticMode::ReadOnly || !accounts.is_empty()),
                    egui::Button::new(if mode == DiagnosticMode::ReadOnly {
                        t.diagnostic_start
                    } else {
                        t.diagnostic_full_start
                    }),
                )
                .clicked()
            {
                diagnostics::start(self.state.clone());
            }
            if diagnostic.running()
                && diagnostic.phase != FunctionalPhase::Restoring
                && ui
                    .button(if mode == DiagnosticMode::Functional {
                        t.diagnostic_cancel_restore
                    } else {
                        t.btn_cancel
                    })
                    .clicked()
            {
                diagnostics::cancel(&self.state);
            }
            if !diagnostic.report.is_empty() && ui.button(t.diagnostic_copy).clicked() {
                // egui's normal clipboard output; no OS process or file I/O here.
                ui.output_mut(|output| output.copied_text = diagnostic.report.clone());
            }
        });
        match diagnostic.status {
            RunStatus::Running => {
                ui.horizontal_wrapped(|ui| {
                    ui.spinner();
                    ui.label(if diagnostic.phase == FunctionalPhase::Restoring {
                        t.diagnostic_restoring
                    } else {
                        t.diagnostic_running
                    });
                });
            }
            RunStatus::Completed => {
                ui.label(t.diagnostic_done);
            }
            RunStatus::Idle => {}
            RunStatus::RestoreFailed => {
                ui.colored_label(ui.visuals().error_fg_color, t.diagnostic_restore_failed);
            }
            _ => {
                ui.label(t.diagnostic_stopped);
            }
        }
        if !can_start && !diagnostic.running() {
            ui.weak(t.diagnostic_wait);
        }
        match diagnostic.save_status {
            SaveStatus::Pending if diagnostic.running() && mode == DiagnosticMode::Functional => {
                ui.small(t.diagnostic_full_memory);
            }
            SaveStatus::Pending if !diagnostic.running() => {
                ui.small(t.diagnostic_saving);
            }
            SaveStatus::Saved => {
                ui.small(t.diagnostic_saved);
                ui.small(crate::path::diagnostic_path().display().to_string());
            }
            SaveStatus::Failed => {
                ui.colored_label(ui.visuals().error_fg_color, t.diagnostic_save_failed);
            }
            _ => {}
        }
        if !diagnostic.report.is_empty() {
            egui::CollapsingHeader::new(t.diagnostic_details)
                .id_salt("diagnostic_report")
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            let mut read_only = diagnostic.report.as_str();
                            ui.add(
                                egui::TextEdit::multiline(&mut read_only)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(ui.available_width())
                                    .desired_rows(5)
                                    .frame(false),
                            );
                        });
                });
        }
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
