use iced::widget::{button, container, text_input};
use iced::{Background, Border, Color, Theme, gradient};

pub(crate) fn desktop_theme() -> Theme {
    Theme::custom(
        "Starlab".to_string(),
        iced::theme::Palette {
            background: Color::from_rgb8(12, 16, 29),
            text: Color::from_rgb8(245, 246, 250),
            primary: Color::from_rgb8(139, 124, 255),
            success: accent(),
            warning: warning(),
            danger: danger(),
        },
    )
}

fn glass(top: Color, bottom: Color) -> Background {
    gradient::Linear::new(std::f32::consts::PI)
        .add_stop(0.0, top)
        .add_stop(1.0, bottom)
        .into()
}

pub(crate) fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(glass(
            Color::from_rgba8(43, 49, 72, 0.84),
            Color::from_rgba8(21, 27, 44, 0.76),
        )),
        text_color: Some(Color::from_rgb8(245, 246, 250)),
        border: Border {
            width: 1.0,
            radius: 18.0.into(),
            color: Color::from_rgba8(221, 226, 255, 0.17),
        },
        ..container::Style::default()
    }
}

pub(crate) fn highlight_style(theme: &Theme) -> container::Style {
    container::Style {
        border: Border {
            color: Color::from_rgba8(169, 151, 255, 0.65),
            ..panel_style(theme).border
        },
        ..panel_style(theme)
    }
}

pub(crate) fn accent() -> Color {
    Color::from_rgb8(32, 185, 125)
}
pub(crate) fn warning() -> Color {
    Color::from_rgb8(230, 170, 69)
}
pub(crate) fn danger() -> Color {
    Color::from_rgb8(242, 104, 120)
}
pub(crate) fn muted() -> Color {
    Color::from_rgb8(171, 181, 204)
}
pub(crate) fn faint() -> Color {
    Color::from_rgb8(218, 225, 243)
}

pub(crate) fn primary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let (top, bottom, border) = match status {
        button::Status::Active => (
            Color::from_rgb8(166, 146, 255),
            Color::from_rgb8(135, 115, 246),
            0.32,
        ),
        button::Status::Hovered => (
            Color::from_rgb8(184, 168, 255),
            Color::from_rgb8(152, 133, 255),
            0.55,
        ),
        button::Status::Pressed => (
            Color::from_rgb8(141, 120, 239),
            Color::from_rgb8(124, 102, 225),
            0.22,
        ),
        button::Status::Disabled => (
            Color::from_rgba8(139, 124, 255, 0.18),
            Color::from_rgba8(139, 124, 255, 0.12),
            0.08,
        ),
    };
    button::Style {
        background: Some(glass(top, bottom)),
        text_color: if status == button::Status::Disabled {
            Color::from_rgb8(149, 157, 180)
        } else {
            Color::from_rgb8(24, 18, 49)
        },
        border: Border {
            radius: 12.0.into(),
            width: 1.0,
            color: Color::from_rgba8(237, 229, 255, border),
        },
        ..button::Style::default()
    }
}

pub(crate) fn secondary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let (top, bottom, edge) = match status {
        button::Status::Active => (
            Color::from_rgba8(83, 92, 126, 0.32),
            Color::from_rgba8(42, 49, 74, 0.50),
            0.16,
        ),
        button::Status::Hovered => (
            Color::from_rgba8(108, 117, 157, 0.42),
            Color::from_rgba8(60, 68, 104, 0.60),
            0.32,
        ),
        button::Status::Pressed => (
            Color::from_rgba8(36, 43, 67, 0.80),
            Color::from_rgba8(31, 36, 59, 0.80),
            0.21,
        ),
        button::Status::Disabled => (
            Color::from_rgba8(56, 65, 91, 0.18),
            Color::from_rgba8(35, 41, 63, 0.24),
            0.07,
        ),
    };
    button::Style {
        background: Some(glass(top, bottom)),
        text_color: if status == button::Status::Disabled {
            Color::from_rgb8(138, 149, 173)
        } else {
            Color::from_rgb8(239, 243, 255)
        },
        border: Border {
            width: 1.0,
            radius: 12.0.into(),
            color: Color::from_rgba8(227, 231, 255, edge),
        },
        ..button::Style::default()
    }
}

pub(crate) fn input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let mut style = text_input::default(theme, status);
    style.border.radius = 12.0.into();
    style.border.width = if matches!(status, text_input::Status::Focused { .. }) {
        2.0
    } else {
        1.0
    };
    style.border.color = match status {
        text_input::Status::Focused { .. } => Color::from_rgb8(170, 151, 255),
        text_input::Status::Hovered => Color::from_rgba8(201, 209, 239, 0.36),
        text_input::Status::Disabled => Color::from_rgba8(201, 209, 239, 0.08),
        text_input::Status::Active => Color::from_rgba8(201, 209, 239, 0.20),
    };
    style.background = glass(
        Color::from_rgba8(14, 19, 36, 0.78),
        Color::from_rgba8(22, 28, 47, 0.68),
    );
    style.value = Color::from_rgb8(239, 243, 255);
    style.placeholder = Color::from_rgb8(152, 165, 190);
    style.selection = Color::from_rgba8(139, 124, 255, 0.42);
    style
}

pub(crate) fn active_nav_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = secondary_button(theme, status);
    if status != button::Status::Disabled {
        style.background = Some(glass(
            Color::from_rgba8(
                133,
                108,
                229,
                match status {
                    button::Status::Hovered => 0.35,
                    button::Status::Pressed => 0.16,
                    _ => 0.26,
                },
            ),
            Color::from_rgba8(68, 56, 128, 0.38),
        ));
        style.border.color = Color::from_rgba8(173, 154, 255, 0.72);
    }
    style
}
