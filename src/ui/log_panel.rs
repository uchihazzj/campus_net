use egui::ScrollArea;

use crate::service::SharedState;
use crate::ui::l10n::UiText;

/// Render the log panel as a collapsing section.
///
/// The panel shows the last 200 log messages in a read-only monospace text area
/// with auto-scroll and a clear button.
pub fn render_log_panel(
    state: &SharedState,
    log_scroll_to_bottom: &mut bool,
    ui: &mut egui::Ui,
    t: &UiText,
) {
    ui.collapsing(t.section_log, |ui| {
        let log_msgs: Vec<String> = {
            let s = state.lock().unwrap();
            s.log_messages.clone()
        };

        let mut text = log_msgs.join("\n");

        ScrollArea::vertical()
            .max_height(200.0)
            .auto_shrink([false; 2])
            .stick_to_bottom(*log_scroll_to_bottom)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });

        ui.horizontal(|ui| {
            ui.checkbox(log_scroll_to_bottom, t.opt_auto_scroll);
            if ui.button(t.btn_clear).clicked() {
                let mut s = state.lock().unwrap();
                s.log_messages.clear();
            }
        });
    });
}
