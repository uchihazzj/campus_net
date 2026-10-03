pub(crate) const DEFAULT_SIZE: [f32; 2] = [520.0, 350.0];
pub(crate) const MIN_SIZE: [f32; 2] = [420.0, 280.0];
const MAX_DIMENSION: f32 = 16_384.0;

#[derive(Debug, PartialEq)]
pub(super) enum WindowAction {
    None,
    Show,
    Hide,
    Quit,
}

pub(super) fn apply_visibility(
    ctx: &egui::Context,
    show_requested: bool,
    hide_on_close: bool,
    force_quit: bool,
) -> WindowAction {
    if force_quit {
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        return WindowAction::Quit;
    }
    if show_requested {
        // A tray request received during this frame must win over an old
        // close-to-tray event. Emit all visibility commands on the UI thread.
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        if ctx.input(|i| i.viewport().minimized == Some(true)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        return WindowAction::Show;
    }
    if ctx.input(|i| i.viewport().close_requested()) {
        if hide_on_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            return WindowAction::Hide;
        }
        return WindowAction::Quit;
    }
    WindowAction::None
}

fn valid_size(size: [f32; 2]) -> bool {
    size.iter()
        .zip(MIN_SIZE)
        .all(|(&value, min)| value.is_finite() && value >= min && value <= MAX_DIMENSION)
}

pub(crate) fn startup_size(width: Option<f32>, height: Option<f32>) -> [f32; 2] {
    let size = [
        width.unwrap_or(DEFAULT_SIZE[0]),
        height.unwrap_or(DEFAULT_SIZE[1]),
    ];
    if valid_size(size) {
        size
    } else {
        DEFAULT_SIZE
    }
}

/// Keep only usable normal-window geometry. Hidden, minimized and maximized
/// viewports must not overwrite the size used for the next launch.
pub(super) fn remember_normal_size(
    config: &mut crate::service::config::AppConfig,
    viewport: &egui::ViewportInfo,
    hidden: bool,
) {
    if hidden
        || viewport.minimized == Some(true)
        || viewport.maximized == Some(true)
        || viewport.fullscreen == Some(true)
    {
        return;
    }
    if let Some(rect) = viewport.inner_rect {
        let size = [rect.width(), rect.height()];
        if valid_size(size) {
            config.window_width = Some(size[0]);
            config.window_height = Some(size[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visibility_output(close: bool, minimized: bool, force_quit: bool) -> egui::FullOutput {
        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        let viewport = input.viewports.entry(egui::ViewportId::ROOT).or_default();
        viewport.minimized = Some(minimized);
        viewport.maximized = Some(!minimized);
        if close {
            viewport.events.push(egui::ViewportEvent::Close);
        }
        ctx.run(input, |ctx| {
            apply_visibility(ctx, true, true, force_quit);
        })
    }

    #[test]
    fn tray_show_wins_over_a_pending_hide() {
        let output = visibility_output(true, false, false);
        let commands = &output.viewport_output[&egui::ViewportId::ROOT].commands;
        assert!(commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::CancelClose)));
        assert!(commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::Visible(true))));
        assert!(!commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::Visible(false))));
    }

    #[test]
    fn showing_maximized_window_does_not_restore_normal_geometry() {
        let output = visibility_output(false, false, false);
        assert!(!output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::Minimized(false))));
    }

    #[test]
    fn showing_minimized_window_restores_and_forced_quit_still_exits() {
        let output = visibility_output(false, true, false);
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::Minimized(false))));
        let output = visibility_output(true, true, true);
        let commands = &output.viewport_output[&egui::ViewportId::ROOT].commands;
        assert!(commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::Close)));
        assert!(!commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::CancelClose)));
    }

    #[test]
    fn tiny_saved_window_recovers_to_default_size() {
        assert_eq!(startup_size(Some(2.4000015), Some(2.4000015)), DEFAULT_SIZE);
    }

    #[test]
    fn valid_saved_size_is_preserved() {
        assert_eq!(startup_size(Some(800.0), Some(600.0)), [800.0, 600.0]);
        assert_eq!(startup_size(None, None), DEFAULT_SIZE);
    }

    #[test]
    fn unusable_saved_sizes_recover() {
        for value in [0.0, -1.0, 2.4, f32::NAN, f32::INFINITY, 100_000.0] {
            assert_eq!(startup_size(Some(value), Some(600.0)), DEFAULT_SIZE);
            assert_eq!(startup_size(Some(800.0), Some(value)), DEFAULT_SIZE);
        }
    }

    #[test]
    fn transient_geometry_does_not_replace_normal_size() {
        let mut config = crate::service::config::AppConfig::default();
        let mut viewport = egui::ViewportInfo {
            inner_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        };
        remember_normal_size(&mut config, &viewport, false);
        for (size, hidden, minimized, maximized) in [
            ([2.4, 2.4], false, false, false),
            ([1920.0, 1080.0], false, false, true),
            ([640.0, 480.0], false, true, false),
            ([640.0, 480.0], true, false, false),
        ] {
            viewport.inner_rect = Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size.into()));
            viewport.minimized = Some(minimized);
            viewport.maximized = Some(maximized);
            remember_normal_size(&mut config, &viewport, hidden);
            assert_eq!(
                [config.window_width.unwrap(), config.window_height.unwrap()],
                [800.0, 600.0]
            );
        }
    }
}
