//! In-memory egui rendering only. Never construct the native app, enumerate
//! interfaces, read runtime config, or call authentication/update entry points.
use std::sync::{Arc, Mutex};

use egui::{epaint::Shape, pos2, vec2, Context, FullOutput, RawInput, Rect};

use super::CampusNetApp;
use crate::service::{
    config::AppConfig, config::StoredUser, AppState, AuthServerStatus, CampusAuthStatus,
    Ipv4InternetStatus, LoginState, OnlineUserInfo, UpdateStatus,
};
use crate::ui::l10n::Lang;

fn fixture(lang: Lang, state: LoginState) -> CampusNetApp {
    let config = AppConfig {
        language: lang,
        users: vec![StoredUser {
            username: "preview-account-with-a-long-name@cmcc".into(),
            encrypted_password: String::new(),
            ip: Some("10.0.0.42".into()),
            if_name: Some("Preview Campus Ethernet".into()),
        }],
        ..Default::default()
    };
    let server = config.server.clone();
    let mut s = AppState::new(config);
    s.campus_ip = Some("10.0.0.42".into());
    s.auth_server = AuthServerStatus::Reachable;
    // Public reachability must not turn an unknown campus session green.
    s.ipv4_internet = Ipv4InternetStatus::Reachable;
    if state == LoginState::Online {
        s.campus_auth = CampusAuthStatus::LoggedIn;
        s.online_info = Some(OnlineUserInfo {
            error: "ok".into(),
            user_name: s.config.users[0].username.clone(),
            online_ip: "10.0.0.42".into(),
            sum_seconds: 3661,
            remain_bytes: 3 * 1024 * 1024 * 1024,
            products_name: "Preview campus plan".into(),
            ..Default::default()
        });
    }
    s.user_statuses[0].state = state;
    s.log_messages = vec!["[10/15 09:30] [INFO] Offline UI preview; synthetic data only".into()];
    CampusNetApp {
        state: Arc::new(Mutex::new(s)),
        _tray_icon: None,
        window_hidden: false,
        pending_delete: None,
        server_draft: server.clone(),
        server_original: server,
        editing_user_idx: None,
        edit_username: String::new(),
        edit_password: String::new(),
        edit_ip: String::new(),
        edit_if_name: String::new(),
        edit_original_username: String::new(),
        edit_original_ip: String::new(),
        edit_original_if_name: String::new(),
        show_add_dialog: false,
        edit_error: false,
        edit_detected_ip: None,
        edit_interfaces: Vec::new(),
        edit_network_rx: None,
    }
}

fn context(light: bool) -> Context {
    let ctx = Context::default();
    ctx.set_theme(if light {
        egui::Theme::Light
    } else {
        egui::Theme::Dark
    });
    super::configure_style(&ctx);
    ctx.style_mut(|style| style.animation_time = 0.0);
    if let Some(font) = crate::load_cjk_font() {
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert("cjk_font".into(), font);
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .get_mut(&family)
                .unwrap()
                .insert(0, "cjk_font".into());
        }
        ctx.set_fonts(fonts);
    }
    ctx
}

fn render(
    app: &mut CampusNetApp,
    size: [f32; 2],
    light: bool,
    name: &str,
) -> (Context, FullOutput) {
    let ctx = context(light);
    let config_before = serde_json::to_value(&app.state.lock().unwrap().config).unwrap();
    let mut textures = egui::TexturesDelta::default();
    let mut output = FullOutput::default();
    for frame in 0..5 {
        output = ctx.run(
            RawInput {
                screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(size[0], size[1]))),
                time: Some(frame as f64 / 60.0),
                ..Default::default()
            },
            |ctx| app.render_content(ctx),
        );
        textures.append(std::mem::take(&mut output.textures_delta));
    }
    output.textures_delta = textures;
    let s = app.state.lock().unwrap();
    assert_eq!(serde_json::to_value(&s.config).unwrap(), config_before);
    assert_eq!((s.auth_generation, s.online_query_generation), (0, 0));
    assert!(!s.auth_busy && !s.online_query_busy && !s.config_save_pending && !s.autostart_busy);
    drop(s);
    export_preview(&ctx, &output, size, name);
    (ctx, output)
}

fn text_rect(shapes: &[egui::epaint::ClippedShape], text: &str) -> Option<Rect> {
    fn find(shape: &Shape, text: &str) -> Option<Rect> {
        match shape {
            Shape::Text(shape) if shape.galley.job.text.contains(text) => {
                Some(Rect::from_min_size(shape.pos, shape.galley.size()))
            }
            Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, text)),
            _ => None,
        }
    }
    shapes.iter().find_map(|shape| {
        find(&shape.shape, text).filter(|rect| shape.clip_rect.contains_rect(*rect))
    })
}

#[test]
fn status_previews_preserve_authentication_and_fit_small_windows() {
    for (lang, prefix) in [(Lang::Chinese, "zh"), (Lang::English, "en")] {
        for (size, suffix) in [([420.0, 280.0], "small"), ([520.0, 700.0], "tall")] {
            for (state, status_name) in [
                (LoginState::Online, "online"),
                (LoginState::PendingConfirm, "pending"),
                (LoginState::LoggedOut, "unknown"),
                (LoginState::Online, "stale"),
            ] {
                let mut app = fixture(lang, state);
                if status_name == "stale" {
                    app.state.lock().unwrap().online_info_stale = true;
                }
                let t = app.t();
                let (_, out) = render(
                    &mut app,
                    size,
                    false,
                    &format!("{prefix}_{status_name}_{suffix}"),
                );
                let expected = match status_name {
                    "online" => t.campus_auth_logged_in,
                    "pending" => t.status_pending_confirm,
                    "stale" => t.status_last_online,
                    _ => t.campus_auth_unknown,
                };
                let status = text_rect(&out.shapes, expected).expect("main status must be visible");
                assert!(
                    status.right() <= size[0] && status.bottom() <= size[1],
                    "{status_name}: {status:?}"
                );
                if suffix == "tall" && status_name == "online" {
                    assert!(text_rect(&out.shapes, "01:01:01").is_some());
                }
                if suffix == "tall" && status_name == "unknown" {
                    assert!(
                        text_rect(&out.shapes, &format!("●  {}", t.status_offline)).is_none(),
                        "unconfirmed account must not look offline"
                    );
                }
            }
        }
    }
    let mut light = fixture(Lang::Chinese, LoginState::Online);
    render(&mut light, [520.0, 700.0], true, "zh_online_light");
}

#[test]
fn account_dialog_actions_remain_inside_the_minimum_window() {
    for (lang, prefix) in [(Lang::Chinese, "zh"), (Lang::English, "en")] {
        let mut app = fixture(lang, LoginState::LoggedOut);
        // Set fields directly: opening the real add action enumerates real interfaces.
        app.show_add_dialog = true;
        app.edit_interfaces = (1..=40)
            .map(|i| {
                (
                    format!("Preview Ethernet adapter with a long name {i}"),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i)),
                )
            })
            .collect();
        app.edit_if_name = app.edit_interfaces[0].0.clone();
        let t = app.t();
        let (ctx, out) = render(
            &mut app,
            [420.0, 280.0],
            false,
            &format!("{prefix}_add_small"),
        );
        let screen = ctx.screen_rect();
        let window = ctx
            .memory(|m| m.area_rect(egui::Id::new("account_edit")))
            .unwrap();
        assert!(
            screen.expand(1.0).contains_rect(window),
            "dialog overflow: {window:?}"
        );
        for label in [t.btn_save, t.btn_cancel] {
            assert!(
                screen.contains_rect(text_rect(&out.shapes, label).expect("dialog action missing"))
            );
        }
        app.show_add_dialog = false;
        app.pending_delete = Some((0, app.state.lock().unwrap().config.users[0].clone()));
        let (ctx, out) = render(
            &mut app,
            [420.0, 280.0],
            false,
            &format!("{prefix}_delete_small"),
        );
        let window = ctx
            .memory(|m| m.area_rect(egui::Id::new("delete_account")))
            .unwrap();
        assert!(
            screen.expand(1.0).contains_rect(window),
            "delete dialog overflow: {window:?}"
        );
        assert!(screen.contains_rect(text_rect(&out.shapes, t.btn_cancel).unwrap()));
    }
}

#[test]
fn version_and_update_actions_stay_visible_in_the_minimum_window() {
    for (lang, prefix) in [(Lang::Chinese, "zh"), (Lang::English, "en")] {
        for (name, status) in [
            ("idle", UpdateStatus::Idle),
            ("checking", UpdateStatus::Checking),
            ("current", UpdateStatus::UpToDate),
            (
                "available",
                UpdateStatus::Available {
                    latest: "v9.9.9".into(),
                    release_url: "https://example.test/release".into(),
                    download_url: "https://example.test/preview.exe".into(),
                },
            ),
            ("downloading", UpdateStatus::Downloading),
            ("preparing", UpdateStatus::PreparingUpdate),
            ("restarting", UpdateStatus::Restarting),
            (
                "failed",
                UpdateStatus::Failed("Preview update error: ".repeat(40)),
            ),
        ] {
            let mut app = fixture(lang, LoginState::Online);
            // A long list must scroll without displacing the version/update controls.
            {
                let mut s = app.state.lock().unwrap();
                for index in 1..20 {
                    let mut user = s.config.users[0].clone();
                    user.username = format!("preview-extra-account-{index}");
                    s.config.users.push(user);
                }
                s.ensure_statuses();
                s.update_status = status;
            }
            let t = app.t();
            let (ctx, out) = render(
                &mut app,
                [420.0, 280.0],
                false,
                &format!("{prefix}_update_{name}_small"),
            );
            for label in [
                t.section_about,
                env!("CARGO_PKG_VERSION"),
                t.btn_check_update,
                "GitHub",
            ] {
                let rect = text_rect(&out.shapes, label).expect("version control must be visible");
                assert!(
                    ctx.screen_rect().contains_rect(rect),
                    "{prefix} {name} {label}: {rect:?}"
                );
            }
            if name == "available" {
                for label in ["v9.9.9", t.btn_auto_update, t.btn_open_release] {
                    assert!(ctx
                        .screen_rect()
                        .contains_rect(text_rect(&out.shapes, label).unwrap()));
                }
            }
            if name == "failed" {
                assert!(
                    text_rect(&out.shapes, t.update_failed).is_some(),
                    "error must fit the footer clip"
                );
                assert!(
                    text_rect(&out.shapes, t.update_failed).unwrap().top()
                        < text_rect(&out.shapes, "GitHub").unwrap().bottom(),
                    "long errors must not force another footer row"
                );
            }
            let main_status = text_rect(&out.shapes, t.campus_auth_logged_in).unwrap();
            assert!(ctx.screen_rect().contains_rect(main_status));
            assert!(main_status.bottom() < text_rect(&out.shapes, t.section_about).unwrap().top());
        }
    }
}

#[test]
fn multiple_accounts_keep_titles_left_aligned_and_session_details_visible() {
    for (lang, prefix) in [(Lang::Chinese, "zh"), (Lang::English, "en")] {
        for light in [false, true] {
            let mut app = fixture(lang, LoginState::Online);
            {
                let mut s = app.state.lock().unwrap();
                s.config.users[0].username = "preview-account-01".into();
                s.config.users[0].ip = None;
                let mut online_user = s.config.users[0].clone();
                online_user.username = "preview-account-02".into();
                s.config.users.push(online_user);
                s.ensure_statuses();
                s.user_statuses[0].state = LoginState::LoggedOut;
                s.user_statuses[1].state = LoginState::Online;
                let info = s.online_info.as_mut().unwrap();
                info.user_name = "preview-account-02".into();
                info.sum_seconds = 3 * 3600 + 16 * 60 + 6;
                info.remain_bytes = 256 * 1024 * 1024 * 1024;
                s.update_status = UpdateStatus::UpToDate;
            }
            let (_, out) = render(
                &mut app,
                [706.0, 830.0],
                light,
                &format!(
                    "{prefix}_two_accounts_{}",
                    if light { "light" } else { "dark" }
                ),
            );
            let title = text_rect(&out.shapes, "preview-account-01").unwrap();
            assert!(
                title.left() < 40.0,
                "account title must start at the card's left inset: {title:?}"
            );
            assert!(text_rect(&out.shapes, "preview-account-02").is_some());
            assert!(text_rect(&out.shapes, "03:16:06").is_some());
            assert!(text_rect(&out.shapes, "256.0 GB").is_some());
            assert!(text_rect(&out.shapes, app.t().update_up_to_date).is_some());
        }
    }
}

#[test]
fn decoded_chinese_server_error_reaches_the_ui_unchanged() {
    let mut app = fixture(Lang::Chinese, LoginState::Error);
    let body = r#"sdu({"error_msg":"忙"})"#;
    let (bytes, _, errors) = encoding_rs::GBK.encode(body);
    assert!(!errors);
    let decoded =
        crate::core::srun::decode_body(&bytes, Some("text/javascript; charset=gbk")).unwrap();
    let json = crate::core::jsonp::strip_jsonp(&decoded).unwrap();
    let response: serde_json::Value = serde_json::from_str(json).unwrap();
    let message = format!("error_msg={}", response["error_msg"].as_str().unwrap());
    assert_eq!(message, "error_msg=忙");
    app.state.lock().unwrap().user_statuses[0].last_error = message.clone();
    let (_, out) = render(&mut app, [520.0, 700.0], false, "zh_server_error");
    assert!(text_rect(&out.shapes, &message).is_some());
}

#[test]
fn expanded_settings_keep_server_drafts_out_of_live_config() {
    let mut app = fixture(Lang::English, LoginState::LoggedOut);
    let before = serde_json::to_value(&app.state.lock().unwrap().config).unwrap();
    app.server_draft = "http://".into();
    let ctx = context(false);
    // Only click the two section headers; never click config/action controls.
    let size = [420.0, 1150.0];
    let mut textures = egui::TexturesDelta::default();
    let mut out = FullOutput::default();
    let mut click = pos2(0.0, 0.0);
    let t = app.t();
    for frame in 0..9 {
        if frame == 2 || frame == 5 {
            click = text_rect(
                &out.shapes,
                if frame == 2 {
                    t.section_settings
                } else {
                    t.section_advanced
                },
            )
            .unwrap()
            .center();
        }
        let events = if matches!(frame, 2 | 3 | 5 | 6) {
            vec![
                egui::Event::PointerMoved(click),
                egui::Event::PointerButton {
                    pos: click,
                    button: egui::PointerButton::Primary,
                    pressed: frame == 2 || frame == 5,
                    modifiers: Default::default(),
                },
            ]
        } else {
            vec![egui::Event::PointerGone]
        };
        out = ctx.run(
            RawInput {
                screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(size[0], size[1]))),
                time: Some(frame as f64 / 60.0),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.render_settings(ui));
            },
        );
        textures.append(std::mem::take(&mut out.textures_delta));
    }
    out.textures_delta = textures;
    let invalid = text_rect(&out.shapes, t.server_invalid_hint).unwrap();
    assert!(ctx.screen_rect().contains_rect(invalid));
    assert!(text_rect(&out.shapes, t.section_auth_params).is_some());
    assert_eq!(
        serde_json::to_value(&app.state.lock().unwrap().config).unwrap(),
        before
    );
    assert!(!app.state.lock().unwrap().config_save_pending);
    export_preview(&ctx, &out, size, "en_settings_small");
}

/// Optional export for offline rasterization of actual egui triangles and atlas.
/// Default tests write nothing. All data above is synthetic.
fn export_preview(ctx: &Context, output: &FullOutput, size: [f32; 2], name: &str) {
    let Ok(dir) = std::env::var("CNET_UI_PREVIEW_DIR") else {
        return;
    };
    use base64::Engine;
    use egui::epaint::{ImageData, Primitive};
    use serde_json::json;
    let textures: Vec<_> = output
        .textures_delta
        .set
        .iter()
        .map(|(id, delta)| {
            let pixels: Vec<_> = match &delta.image {
                ImageData::Color(image) => image.pixels.clone(),
                ImageData::Font(image) => image.srgba_pixels(None).collect(),
            };
            let bytes: Vec<_> = pixels.iter().flat_map(|color| color.to_array()).collect();
            json!({"id": format!("{id:?}"), "size": delta.image.size(), "pos": delta.pos,
            "rgba": base64::engine::general_purpose::STANDARD.encode(bytes)})
        })
        .collect();
    let meshes: Vec<_> = ctx.tessellate(output.shapes.clone(), output.pixels_per_point).into_iter().filter_map(|clipped| {
        let Primitive::Mesh(mesh) = clipped.primitive else { return None; };
        let vertices: Vec<_> = mesh.vertices.iter().map(|v| json!([
            v.pos.x, v.pos.y, v.uv.x, v.uv.y, v.color.r(), v.color.g(), v.color.b(), v.color.a()
        ])).collect();
        Some(json!({"texture": format!("{:?}", mesh.texture_id), "vertices": vertices, "indices": mesh.indices,
            "clip": [clipped.clip_rect.min.x, clipped.clip_rect.min.y, clipped.clip_rect.max.x, clipped.clip_rect.max.y]}))
    }).collect();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        std::path::Path::new(&dir).join(format!("{name}.json")),
        serde_json::to_vec(&json!({"size": size, "textures": textures, "meshes": meshes})).unwrap(),
    )
    .unwrap();
}
