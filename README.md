# Starlab Desktop

Native desktop **MPC wallet** — an [Iced](https://iced.rs) GUI (MIT) over the
[`starlab-mpc`](https://github.com/stars-labs/starlab-mpc) threshold-signing
engine. Create and use a multi-device wallet whose keys are split across
devices (DKG + threshold signing over a WebRTC mesh); no single device ever
holds a whole key. A wallet has a threshold-ECDSA key (cggmp24) for its
Ethereum accounts — signatures are standard `r ‖ s ‖ v`, `ecrecover`-compatible
— and FROST keys for Bitcoin (Taproot, BIP-340) and, on an ed25519 device,
Solana / Sui.

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
approve or reject a peer's signature request, and export / import this
device's encrypted key shares — one file per key, `<wallet>-<curve>.json`
(`MPC_EXPORT_PATH` = a folder, `MPC_IMPORT_PATH` = a file or a folder; both
skip the file dialog on machines without a desktop file portal). The SD-card
air-gap is not exposed.

The Ethereum key needs Paillier safe primes, which take minutes of CPU: the
app generates them in the background from launch and shows "ECDSA setup:
preparing safe primes (…)" / "ready" in the sidebar. A wallet setup started
before they are ready waits for them (the setup banner says so).

```bash
cargo test                             # unit + headless UI tests (iced_test)
cargo test -- --ignored                # 3 devices: create, sign, export/import (loopback)
SNAPSHOT_DIR=/tmp/shots cargo test snapshots   # render the main screens to PNG
```

## Dependency note

`starlab-client` is a git dependency on `starlab-mpc`. While threshold ECDSA is
being integrated it tracks the `feat/ecdsa-cggmp24` branch; it goes back to
`main` when that branch merges. For releases, pin it to a tag or rev.
