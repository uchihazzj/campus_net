use egui::Color32;

use super::CampusNetApp;
use crate::service::UpdateStatus;

impl CampusNetApp {
    pub(super) fn render_version_section(&mut self, ui: &mut egui::Ui) {
        let t = self.t();
        let status = {
            let s = self.state.lock().unwrap();
            s.update_status.clone()
        };

        let busy = matches!(
            status,
            UpdateStatus::Checking
                | UpdateStatus::Downloading
                | UpdateStatus::PreparingUpdate
                | UpdateStatus::Restarting
        );

        ui.horizontal(|ui| {
            ui.label(format!(
                "{} v{}",
                t.version_label,
                env!("CARGO_PKG_VERSION")
            ));

            if ui
                .add_enabled(!busy, egui::Button::new(t.btn_check_update))
                .clicked()
            {
                let state = self.state.clone();
                if crate::service::update_scheduler::try_begin_update_check(&state) {
                    tokio::spawn(async move {
                        let _ =
                            crate::service::update_scheduler::check_update_claimed(&state).await;
                    });
                }
            }
        });

        ui.horizontal(|ui| match &status {
            UpdateStatus::Idle => {}
            UpdateStatus::Checking => {
                ui.colored_label(Color32::GRAY, t.update_checking);
            }
            UpdateStatus::UpToDate => {
                ui.colored_label(Color32::GREEN, t.update_up_to_date);
            }
            UpdateStatus::Available {
                latest,
                release_url,
                download_url,
            } => {
                ui.colored_label(Color32::YELLOW, t.update_available.replace("{}", latest));
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
                ui.colored_label(Color32::YELLOW, t.update_downloading);
            }
            UpdateStatus::PreparingUpdate => {
                ui.colored_label(Color32::YELLOW, t.update_preparing);
            }
            UpdateStatus::Restarting => {
                ui.colored_label(Color32::GREEN, t.update_restarting);
            }
            UpdateStatus::Failed(e) => {
                ui.colored_label(Color32::RED, format!("{}: {}", t.update_failed, e));
            }
        });
    }
}
