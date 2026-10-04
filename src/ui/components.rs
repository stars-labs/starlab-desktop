use super::assets::{Glyph, glyph};
use super::theme::*;
use crate::*;
use iced::widget::{Row, Space, button, column, container, row, text, text_input};
use iced::{Alignment, Background, Color, Element, Length};

pub(crate) fn card<'a>(title: &'a str, body: Element<'a, Message>) -> Element<'a, Message> {
    let icon = if title.contains("Backup") {
        Glyph::Backup
    } else if title.contains("Sign") {
        Glyph::Sign
    } else if title == "Activity" {
        Glyph::Activity
    } else if title == "Network" {
        Glyph::Connection
    } else {
        Glyph::Wallet
    };
    container(
        column![
            row![glyph(icon, 24.0), text(title).size(18)]
                .spacing(10)
                .align_y(Alignment::Center),
            body
        ]
        .spacing(16),
    )
    .padding(20)
    .width(Length::Fill)
    .style(panel_style)
    .into()
}

/// A labelled form field.
pub(crate) fn field<'a>(
    label: &'a str,
    input: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    column![text(label).size(12).color(muted()), input.into()]
        .spacing(4)
        .into()
}

pub(crate) fn hint(message: &str) -> Element<'_, Message> {
    text(message).size(12).color(muted()).into()
}

/// A right-aligned primary action with the reason it's disabled on the left.
pub(crate) fn action_row<'a>(
    action: iced::widget::Button<'a, Message>,
    blocker: Option<&'a str>,
) -> Element<'a, Message> {
    // The reason takes the remaining width and wraps; the button keeps its
    // size, so a long reason in a narrow card can't squeeze it away.
    row![
        text(blocker.unwrap_or_default())
            .size(12)
            .color(warning())
            .width(Length::Fill),
        action,
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .into()
}

/// A command button (Connect, Create wallet, Copy, …).
pub(crate) fn action_button(label: &str) -> iced::widget::Button<'_, Message> {
    button(text(label).size(14))
        .padding([12, 16])
        .style(secondary_button)
}

pub(crate) fn tab_button(label: &str, tab: Tab, active: Tab) -> iced::widget::Button<'_, Message> {
    let icon = match tab {
        Tab::Setup => Glyph::Setup,
        Tab::Sign => Glyph::Sign,
        Tab::Activity => Glyph::Activity,
        Tab::Connection => Glyph::Connection,
        Tab::Backup => Glyph::Backup,
    };
    button(
        row![glyph(icon, 20.0), text(label).size(14)]
            .spacing(12)
            .align_y(Alignment::Center),
    )
    .padding([12, 16])
    .style(if tab == active {
        active_nav_button
    } else {
        secondary_button
    })
    .on_press(Message::TabSelected(tab))
}

pub(crate) fn section_divider<'a>() -> Element<'a, Message> {
    container(Space::new().height(1))
        .height(1)
        .width(Length::Fill)
        .style(|_theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(72, 78, 88))),
            ..container::Style::default()
        })
        .into()
}

pub(crate) fn short_addr(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}…{}", &addr[..10], &addr[addr.len() - 6..])
    } else {
        addr.to_string()
    }
}

pub(crate) fn ceremony_steps(active: usize) -> Element<'static, Message> {
    let mut steps = Row::new().spacing(12);
    for (i, label) in ["Connect devices", "Secure setup", "Create wallet", "Ready"]
        .into_iter()
        .enumerate()
    {
        steps = steps.push(
            column![
                text(if i < active {
                    "✓"
                } else if i == active {
                    "●"
                } else {
                    "○"
                })
                .size(16)
                .color(if i == active {
                    iced::Color::from_rgb8(139, 124, 255)
                } else {
                    muted()
                }),
                text(label)
                    .size(11)
                    .color(if i == active { faint() } else { muted() })
            ]
            .spacing(4)
            .width(Length::Fill),
        );
    }
    steps.into()
}

pub(crate) fn new_password_fields<'a>(
    password: &str,
    confirm: &str,
    field_id: PasswordField,
    confirm_id: PasswordField,
) -> Element<'a, Message> {
    column![
        row![
            container(field(
                "Password",
                password_input("At least 8 characters", password, field_id)
            ))
            .width(Length::Fill),
            container(field(
                "Confirm password",
                password_input("Repeat it", confirm, confirm_id)
            ))
            .width(Length::Fill),
        ]
        .spacing(10),
        hint("Encrypts this device's key share. You'll need it to sign."),
    ]
    .spacing(4)
    .into()
}

pub(crate) fn password_input(
    placeholder: &str,
    value: &str,
    field: PasswordField,
) -> Element<'static, Message> {
    text_input(placeholder, value)
        .padding(12)
        .style(input_style)
        .secure(true)
        .on_input(move |v| Message::PasswordChanged(field, v))
        .into()
}
