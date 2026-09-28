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
view(&State)->Element<Message>  <->  update(&mut State, Message)  <->  core_adapter.rs  ->  engine HeadlessRunner
   ▲ widgets emit Message               ▲ Message::Ui(UiEvent)              │ on_sync: model → UiEvent
   |        Subscription::run(ui_bridge)─┘                                   ↓
   |<─────── reads the mpsc receiver ◄──────────────────────────────── UiEvent channel
```

- **Elm structure** (`State` / `Message` / `update` / `view`) maps onto the
  `starlab-mpc` Elm core.
- **Engine bridge**: the runner's `on_sync` hook mirrors its model — wallets,
  invites and signing requests, connection, DKG progress — into `UiEvent`s;
  `NativeUICallback` forwards the signing manager's progress. An Iced
  `Subscription` drains the channel into `Message::Ui`.
- **Layout**: the left column holds what everything else depends on — Network
  (server + room ID) and Wallets (account picker, wallet password). The main
  area follows the flow: *Set up wallet* (create / join) → *Sign* → *Activity*.
  A running wallet setup and peers' signature requests are pinned above the
  tabs; a status bar shows the latest result or error.

## Status

Every flow runs on the real engine: connect, create or join a 2-of-3 wallet
(DKG), cancel a setup (withdraws the invite), sign with any account and chain,
and co-sign a peer's request. Keystore import/export and the SD-card air-gap
are not exposed — the engine's desktop-side managers for them are placeholders.

```bash
cargo test                             # unit + headless UI tests (iced_test)
cargo test -- --ignored                # 3 devices: create a wallet, then sign (loopback)
SNAPSHOT_DIR=/tmp/shots cargo test snapshots   # render the main screens to PNG
```

## Dependency note

`starlab-client` is pinned to `starlab-mpc` `main` (a git dependency). For releases,
pin it to a tag or rev.
