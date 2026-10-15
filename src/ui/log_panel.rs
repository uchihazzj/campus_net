use egui::ScrollArea;

use crate::service::SharedState;
use crate::ui::l10n::UiText;

/// Render the log panel as a collapsing section.
///
/// The panel shows the last 200 log messages in a read-only monospace text area
/// with newest messages at the top and a clear button.
pub fn render_log_panel(state: &SharedState, ui: &mut egui::Ui, t: &UiText) {
    ui.collapsing(t.section_log, |ui| {
        let text: String = {
            let s = state.lock().unwrap();
            s.log_messages
                .iter()
                .rev()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };

        ScrollArea::vertical()
            .max_height(200.0)
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let mut read_only = text.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut read_only)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(5)
                        .frame(false),
                );
            });

        ui.horizontal(|ui| {
            if ui.button(t.btn_copy).clicked() {
                ui.output_mut(|output| output.copied_text = text.clone());
            }
            if ui.button(t.btn_clear).clicked() {
                let mut s = state.lock().unwrap();
                s.log_messages.clear();
            }
        });
    });
}
