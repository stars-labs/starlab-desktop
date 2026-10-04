use crate::Message;
use iced::Element;
use iced::widget::{image, svg};

pub(crate) fn chain_icon(chain: &str, size: f32) -> Element<'static, Message> {
    if chain.eq_ignore_ascii_case("sui") {
        return image(image::Handle::from_bytes(
            include_bytes!("assets/sui.png").as_slice(),
        ))
        .width(size)
        .height(size)
        .into();
    }
    let bytes: &[u8] = match chain.to_ascii_lowercase().as_str() {
        "bitcoin" => include_bytes!("assets/btc.svg"),
        "solana" => include_bytes!("assets/sol.svg"),
        "ethereum" => include_bytes!("assets/eth.svg"),
        _ => br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#313a50"/><circle cx="12" cy="12" r="5" fill="none" stroke="#a1abc0" stroke-width="1.5"/></svg>"##,
    };
    svg(svg::Handle::from_memory(bytes.to_vec()))
        .width(size)
        .height(size)
        .into()
}

#[derive(Clone, Copy)]
pub(crate) enum Glyph {
    Wallet,
    Setup,
    Sign,
    Activity,
    Connection,
    Backup,
    Account,
    Check,
}

pub(crate) fn glyph(icon: Glyph, size: f32) -> Element<'static, Message> {
    let path = match icon {
        Glyph::Wallet => "<path d='M3 7h16v14H3zM3 7V4h14v3M15 12h6v5h-6z'/>",
        Glyph::Setup => "<path d='M12 3v18M3 12h18'/>",
        Glyph::Sign => "<path d='m4 16-1 5 5-1L21 7l-5-5ZM13 5l5 5'/>",
        Glyph::Activity => "<path d='M3 12h4l3-8 4 16 3-8h4'/>",
        Glyph::Connection => {
            "<rect x='2' y='4' width='8' height='14' rx='2'/><rect x='14' y='4' width='8' height='14' rx='2'/><path d='M10 11h4M5 21h2M17 21h2'/>"
        }
        Glyph::Backup => "<path d='m12 2 8 3v7c0 5-8 10-8 10S4 17 4 12V5ZM8 12l3 3 5-6'/>",
        Glyph::Account => "<circle cx='12' cy='8' r='4'/><path d='M4 21v-2a8 8 0 0 1 16 0v2'/>",
        Glyph::Check => "<circle cx='12' cy='12' r='10'/><path d='m7 12 3 3 7-7'/>",
    };
    let document = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#a1abc0' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>{path}</svg>"
    );
    svg(svg::Handle::from_memory(document.into_bytes()))
        .width(size)
        .height(size)
        .into()
}
