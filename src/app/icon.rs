use tray_icon::Icon;

pub(super) fn create_tray_icon_rgba() -> Icon {
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist < 13.0 && dist > 9.0 {
                rgba.extend_from_slice(&[66, 133, 244, 255]);
            } else if dist <= 9.0 && dist > 5.0 {
                rgba.extend_from_slice(&[100, 160, 255, 255]);
            } else if dist <= 5.0 {
                rgba.extend_from_slice(&[255, 255, 255, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, size, size).unwrap_or_else(|e| {
        tracing::error!("Failed to create tray icon rgba: {}, using fallback", e);
        Icon::from_rgba(vec![0, 0, 0, 0], 1, 1)
            .unwrap_or_else(|_| Icon::from_rgba(vec![0, 0, 0, 0], 1, 1).unwrap())
    })
}

pub fn create_window_icon() -> egui::IconData {
    let size = 32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist < 13.0 && dist > 9.0 {
                rgba.extend_from_slice(&[66, 133, 244, 255]);
            } else if dist <= 9.0 && dist > 5.0 {
                rgba.extend_from_slice(&[100, 160, 255, 255]);
            } else if dist <= 5.0 {
                rgba.extend_from_slice(&[255, 255, 255, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}
