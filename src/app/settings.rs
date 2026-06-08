use super::CampusNetApp;
use crate::platform::autostart;
use crate::service::Ipv4InternetStatus;
use crate::ui::l10n::Lang;

impl CampusNetApp {
    pub(super) fn render_settings(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        ui.collapsing(t.section_settings, |ui| {
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

            ui.horizontal(|ui| {
                ui.label(t.label_language);
                if ui
                    .selectable_label(lang == Lang::English, Lang::English.as_str())
                    .clicked()
                {
                    lang = Lang::English;
                    changed = true;
                }
                if ui
                    .selectable_label(lang == Lang::Chinese, Lang::Chinese.as_str())
                    .clicked()
                {
                    lang = Lang::Chinese;
                    changed = true;
                }
            });
            ui.separator();

            ui.label(t.section_auth_params);
            ui.horizontal(|ui| {
                ui.label(t.label_n);
                changed |= ui
                    .add(egui::DragValue::new(&mut n).range(1..=999))
                    .changed();
                ui.label(t.label_type);
                changed |= ui
                    .add(egui::DragValue::new(&mut utype).range(1..=99))
                    .changed();
                ui.label(t.label_acid);
                changed |= ui
                    .add(egui::DragValue::new(&mut acid).range(1..=999))
                    .changed();
            });

            ui.horizontal(|ui| {
                ui.label(t.label_os);
                changed |= ui.text_edit_singleline(&mut os).changed();
                ui.label(t.label_name);
                changed |= ui.text_edit_singleline(&mut name).changed();
            });

            ui.separator();
            ui.label(t.section_network_options);
            changed |= ui.checkbox(&mut detect_ip, t.opt_detect_ip).changed();
            changed |= ui
                .checkbox(&mut strict_bind, t.opt_strict_bind)
                .on_hover_text(t.opt_strict_bind_hint)
                .changed();
            changed |= ui.checkbox(&mut double_stack, t.opt_double_stack).changed();

            ui.separator();
            ui.label(t.section_retry_options);
            ui.horizontal(|ui| {
                ui.label(t.label_retry_times);
                changed |= ui
                    .add(egui::DragValue::new(&mut retry_times).range(1..=99))
                    .changed();
                ui.label(t.label_retry_delay);
                changed |= ui
                    .add(egui::DragValue::new(&mut retry_delay).range(100..=30000))
                    .changed();
            });

            ui.separator();
            ui.label(t.section_app_options);
            changed |= ui
                .checkbox(&mut auto_reconnect, t.opt_auto_reconnect)
                .changed();
            changed |= ui
                .checkbox(&mut minimize_to_tray, t.opt_minimize_tray)
                .changed();

            let as_changed = ui.checkbox(&mut auto_start, t.opt_auto_start).changed();
            if as_changed {
                let result = if auto_start {
                    autostart::enable_autostart()
                } else {
                    autostart::disable_autostart()
                };
                if let Err(e) = result {
                    tracing::error!("Failed to change autostart: {}", e);
                    auto_start = !auto_start;
                }
                changed = true;
            }

            changed |= ui
                .checkbox(&mut enable_ipv4_internet_probe, t.enable_ipv4_probe)
                .on_hover_text(t.enable_ipv4_probe_hint)
                .changed();

            let old_interval = monitor_interval;
            ui.label(t.label_monitor_interval);
            let interval_changed = ui
                .add(
                    egui::DragValue::new(&mut monitor_interval)
                        .range(15..=300)
                        .suffix(format!(" {}", t.seconds_unit)),
                )
                .changed();
            if interval_changed && monitor_interval != old_interval {
                let mut s = self.state.lock().unwrap();
                s.add_log(format!(
                    "[INFO] Network check interval changed to {}s",
                    monitor_interval
                ));
            }
            changed |= interval_changed;

            if changed {
                {
                    let mut s = self.state.lock().unwrap();
                    s.config.language = lang;
                    s.config.auto_reconnect = auto_reconnect;
                    s.config.minimize_to_tray = minimize_to_tray;
                    s.config.auto_start = auto_start;
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
                }
                self.save_config();
            }
        });
    }
}
