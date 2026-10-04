use iced::widget::container;
use iced::{Background, Border, Color, Theme};

pub(crate) fn desktop_theme() -> Theme {
    Theme::custom(
        "Starlab".to_string(),
        iced::theme::Palette {
            background: Color::from_rgb8(17, 19, 27),
            text: Color::from_rgb8(245, 246, 250),
            primary: Color::from_rgb8(139, 124, 255),
            success: accent(),
            warning: warning(),
            danger: danger(),
        },
    )
}
pub(crate) fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb8(25, 29, 41))),
        text_color: Some(Color::from_rgb8(245, 246, 250)),
        border: Border {
            width: 1.0,
            radius: 16.0.into(),
            color: Color::from_rgb8(49, 58, 80),
        },
        ..container::Style::default()
    }
}
pub(crate) fn highlight_style(theme: &Theme) -> container::Style {
    container::Style {
        border: Border {
            color: Color::from_rgb8(139, 124, 255),
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
    Color::from_rgb8(161, 171, 192)
}
pub(crate) fn faint() -> Color {
    Color::from_rgb8(205, 213, 229)
}

pub(crate) fn primary_button(
    theme: &Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let mut style = iced::widget::button::primary(theme, status);
    style.border.radius = 10.0.into();
    style
}
pub(crate) fn secondary_button(
    theme: &Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let mut style = iced::widget::button::secondary(theme, status);
    style.border.radius = 10.0.into();
    style.text_color = Color::from_rgb8(245, 246, 250);
    style.border.width = 1.0;
    style.border.color = Color::from_rgb8(49, 58, 80);
    style.background = Some(Background::Color(Color::from_rgb8(34, 40, 58)));
    style
}
pub(crate) fn input_style(
    theme: &Theme,
    status: iced::widget::text_input::Status,
) -> iced::widget::text_input::Style {
    let mut style = iced::widget::text_input::default(theme, status);
    style.border.radius = 10.0.into();
    style.background = Background::Color(Color::from_rgb8(17, 19, 27));
    style
}

pub(crate) fn active_nav_button(
    theme: &Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let mut style = secondary_button(theme, status);
    style.border.color = Color::from_rgb8(139, 124, 255);
    style.border.width = 2.0;
    style
}
