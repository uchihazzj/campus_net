use super::presentation::{tone_color, Tone};
use super::CampusNetApp;
use crate::service::UpdateStatus;

impl CampusNetApp {
    pub(super) fn render_version_section(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let status = {
            let s = self.state.lock().unwrap();
            s.update_status.clone()
        };

        let busy = crate::service::update_scheduler::update_busy(&status);

        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new(t.btn_check_update))
                    .clicked()
                {
                    let state = self.state.clone();
                    if crate::service::update_scheduler::try_begin_update_check(&state) {
                        tokio::spawn(async move {
                            let _ = crate::service::update_scheduler::check_update_claimed(&state)
                                .await;
                        });
                    }
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.strong(t.section_about);
                    ui.label(format!("v{}", env!("CARGO_PKG_VERSION")))
                        .on_hover_text(t.version_label);
                });
            });
        });

        ui.horizontal_wrapped(|ui| {
            ui.hyperlink_to("GitHub", "https://github.com/uchihazzj/campus_net");
            match &status {
                UpdateStatus::Idle => {}
                UpdateStatus::Checking => {
                    ui.spinner();
                    ui.weak(t.update_checking);
                }
                UpdateStatus::UpToDate => {
                    ui.colored_label(tone_color(ui, Tone::Positive), t.update_up_to_date);
                }
                UpdateStatus::Available {
                    latest,
                    release_url,
                    download_url,
                } => {
                    ui.colored_label(
                        tone_color(ui, Tone::Warning),
                        t.update_available.replace("{}", latest),
                    );
                    ui.add_space(4.0);

                    if ui.button(t.btn_auto_update).clicked() {
                        let state = self.state.clone();
                        let ver = latest.clone();
                        let url = download_url.clone();
                        tokio::spawn(async move {
                            crate::service::update::perform_update(state, ver, url).await;
                        });
                    }

                    ui.hyperlink_to(t.btn_open_release, release_url);
                }
                UpdateStatus::Downloading => {
                    ui.spinner();
                    ui.colored_label(tone_color(ui, Tone::Warning), t.update_downloading);
                }
                UpdateStatus::PreparingUpdate => {
                    ui.colored_label(tone_color(ui, Tone::Warning), t.update_preparing);
                }
                UpdateStatus::Restarting => {
                    ui.colored_label(tone_color(ui, Tone::Positive), t.update_restarting);
                }
                UpdateStatus::Failed(e) => {
                    let message = format!("{}: {}", t.update_failed, e);
                    // A non-wrapping child uses the remaining row width for truncation.
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&message).color(tone_color(ui, Tone::Error)),
                            )
                            .truncate(),
                        )
                        .on_hover_text(message);
                    });
                }
            }
        });
    }
}
