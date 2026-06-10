# Starlab Desktop

Native desktop **MPC wallet** — an [Iced](https://iced.rs) GUI (MIT) over the
[`starlab-mpc`](https://github.com/stars-labs/starlab-mpc) FROST threshold-signing
engine. Create and use a multi-device wallet whose key is split across devices
(FROST DKG + threshold signing over a WebRTC mesh); no single device ever holds
the whole key.

It reuses `starlab-mpc`'s `starlab-client` library (the Elm core + `core::*Manager` +
`HeadlessRunner`) as its business-logic backend — same real DKG / signing /
keystore code as the terminal client, a different shell.

## Build & run

```bash
cargo run            # build + launch the desktop app
cargo build
```

Needs graphics/system libs (wgpu/winit + fontconfig/freetype, plus Wayland/X11
on Linux). `nix develop` provides them all; otherwise install the equivalents
for your platform.

## Architecture

```
view(&State)->Element<Message>  <->  update(&mut State, Message)  <->  core_adapter.rs  ->  starlab_client::core::*Manager
   ▲ widgets emit Message               ▲ Message::Ui(UiEvent)              | UICallback events
   |        Subscription::run(ui_bridge)─┘                                   ↓
   |<─────── reads the mpsc receiver ◄── NativeUICallback (ui_callback.rs) sends UiEvent
```

- **Elm structure** (`State` / `Message` / `update` / `view`) maps onto the
  `starlab-mpc` Elm core.
- **Async→UI bridge**: `NativeUICallback` pushes `UiEvent`s into a
  `tokio::sync::mpsc` channel; an Iced `Subscription` drains them into
  `Message::Ui`. `Send`-clean, no event-loop handle juggling.
- **`core_adapter.rs`** wraps `starlab_client::core::*` managers (UI-agnostic).
- **SD-card air-gap**: export/import dirs `starlab_export` / `starlab_import`
  — MUST match `starlab-mpc`'s `starlab-client` `offline_manager.rs` for desktop↔TUI
  interop.

## Status

Ported from Slint to Iced (Slint's licensing is unsuitable for a proprietary
product). All screens render and primary actions are wired. **Approve & Sign
runs the real FROST ceremony** via `starlab-mpc`'s `SigningBackend` (the same
elm signing path the TUI/CLI use). Remaining gaps: two secondary screens
(per-participant DKG round table, pending-SD-ops list) are `// TODO(iced)`
and currently drop their event data; live multi-device signing from the GUI
still needs an on-device verification pass.

## Dependency note

`starlab-client` is pinned to `starlab-mpc` `main` (a git dependency). For releases,
pin it to a tag or rev.
