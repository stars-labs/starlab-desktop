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

Set `MPC_KEYSTORE_PATH` to use a separate keystore directory (the default is
`~/.frost_keystore`). `MPC_DEVICE_ID`, `MPC_SIGNAL_SERVER`, and `MPC_ROOM`
configure the device and its signaling connection.

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
- **Layout**: the sidebar selects wallets and accounts and navigates to wallet
  setup, signing, activity, connection/devices, and backup/restore. Connection
  settings and backup passwords live in their dedicated panels. Running setup
  and incoming signature requests stay above the main flow.
- **Visuals**: `src/ui/` owns the desktop palette, reusable presentation, and
  locally embedded native-chain assets; `src/ui/assets/PROVENANCE.md` records
  the same asset sources used by the browser extension. Chain marks remain
  available without an internet connection.

## Status

Every flow runs on the real engine: connect, create or join a 2-of-3 wallet
(DKG), cancel a setup (withdraws the invite), sign with any account and chain,
approve or reject a peer's signature request, and export / import this
device's encrypted key shares — one file per key, `<wallet>-<curve>.json`
(`MPC_EXPORT_PATH` = a folder, `MPC_IMPORT_PATH` = a file or a folder; both
skip the file dialog on machines without a desktop file portal). The SD-card
air-gap is not exposed.

The Ethereum key needs Paillier safe primes, which take minutes of CPU: the
app generates them in the background from launch and shows "Secure setup:
preparing (…)" / "ready" under Connection. A wallet setup started
before they are ready waits for them (the setup banner says so).

```bash
cargo test                             # unit + headless UI tests (iced_test)
cargo test -- --ignored                # 3 devices: create, sign, export/import (loopback)
SNAPSHOT_DIR=/tmp/shots cargo test snapshots   # normal + 1024x768 feature states and manifest
```

For a CPU-only Xvfb session, set `ICED_BACKEND=tiny-skia` when launching the
app. The native screenshot harness also uses tiny-skia. The default wgpu
renderer showed uneven small-text spacing under software GPU rendering in
Xvfb; the same release with tiny-skia rendered clearly. The normal desktop
backend selection remains unchanged.

## Dependency note

`starlab-client`, `starlab-core`, and the test signal server share the pinned
engine revision `3c5982d0d458fce1a04c393a679fb5a91a2a168f`. This is the pushed
integrated ECDSA engine, including the fixes reviewed in engine PR135.
`Cargo.lock` records the same revision, so the committed desktop builds and
tests reproduce the reviewed engine without a local dependency override.
Update all three revisions together when adopting a subsequent engine release.
