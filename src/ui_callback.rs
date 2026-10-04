//! Events flowing from the async core into the Iced app.
//!
//! Iced consumes external events through a `Subscription`, so the bridge is
//! a `tokio::sync::mpsc::UnboundedSender<UiEvent>`: the core pushes
//! `UiEvent`s, the app's subscription drains the receiver and turns each
//! one into a `Message::Ui(..)` handled in `update`.
//!
//! Two producers feed the channel: the runner's `on_sync` hook (wallets,
//! sessions, connection, DKG progress — read straight from the engine's
//! model, see `core_adapter`) and [`NativeUICallback`], which the signing
//! manager drives.

use async_trait::async_trait;
use starlab_client::core::{
    ConnectionInfo, OperationMode, ParticipantInfo, SDCardOperation, SessionInfo, SigningRequest,
    SigningState, UICallback, WalletInfo,
};
use tokio::sync::mpsc::UnboundedSender;

/// A wallet grouped across its keys for display: one entry per `wallet_id`,
/// with the group key of every key file it holds (secp256k1-ecdsa → Ethereum;
/// secp256k1 → Bitcoin; ed25519 → Solana + Sui). Addresses are
/// NOT carried here — the view derives them per BIP-44 account from the group
/// key via `starlab_core::accounts` (public-only, cheap), so switching
/// accounts is a pure `State` change with no async round-trip. The root
/// group-key address is never shown: account 0 is the default identity.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletView {
    pub id: String,
    pub name: String,
    pub threshold: String,
    /// (curve_type, group_public_key_hex) — one entry per key this wallet
    /// holds: "secp256k1-ecdsa" (Ethereum, threshold ECDSA), "secp256k1"
    /// (Bitcoin, FROST Taproot), "ed25519" (Solana + Sui).
    pub keys: Vec<(String, String)>,
}

/// The "ECDSA setup" of this device: the Paillier safe primes the next
/// wallet's Ethereum (threshold-ECDSA) key needs. They are generated in the
/// background from startup (minutes of CPU); a wallet setup started before
/// they are ready waits for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaSetup {
    /// An ed25519 device: no Ethereum key, nothing to prepare.
    NotNeeded,
    /// Generating, for `elapsed_secs` so far.
    Preparing {
        elapsed_secs: u64,
    },
    Ready,
}

impl EcdsaSetup {
    /// One status line, e.g. "ECDSA setup: preparing safe primes (1m 12s so
    /// far, usually 1-5 min)"; `None` when there's nothing to show.
    pub fn describe(&self) -> Option<String> {
        match self {
            Self::NotNeeded => None,
            Self::Preparing { elapsed_secs } => Some(format!(
                "ECDSA setup: preparing safe primes ({} so far, usually 1-5 min)",
                format_elapsed(*elapsed_secs)
            )),
            Self::Ready => Some("ECDSA setup: ready".to_string()),
        }
    }
}

/// "42s" / "1m 12s".
pub fn format_elapsed(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {:02}s", secs / 60, secs % 60)
    }
}

/// A new-wallet (DKG) session announced in the room. Peers' signing
/// requests reach the UI through the signing manager instead
/// (`UiEvent::SigningRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct Invite {
    pub id: String,
    pub proposer: String,
    /// Devices that have joined so far (the proposer included).
    pub participants: Vec<String>,
    pub threshold: u16,
    pub total: u16,
}

/// One UI-state mutation pushed from the async core into the Iced app.
#[derive(Debug, Clone)]
pub enum UiEvent {
    Connected(bool),
    /// Peers with an open WebRTC data channel to this device.
    Peers(usize),
    Wallets(Vec<WalletView>),
    Invites(Vec<Invite>),
    ActiveSession(Option<Invite>),
    DkgStatus {
        active: bool,
        round: u8,
        progress: f32,
    },
    /// The runner has a wallet ceremony open — as creator (invite announced)
    /// or joiner (joined, waiting for DKG). Cleared on finalize/cancel.
    CeremonyOpen(bool),
    /// The FROST keys of the running wallet setup are done and its Ethereum
    /// key (threshold ECDSA: safe primes → aux info → keygen) is being made.
    EcdsaKeygen {
        running: bool,
        phase: Option<starlab_client::protocal::ecdsa::DkgPhase>,
    },
    /// This device's safe-prime generator, polled once a second.
    EcdsaSetup(EcdsaSetup),
    /// The signing manager's current request: ours while we sign, or a
    /// peer's (`session_id` set) waiting for this device to approve.
    SigningRequest(Option<SigningRequest>),
    SigningState(SigningState),
    SigningComplete(String),
    Message {
        log_line: String,
        status: String,
        is_error: bool,
    },
    Progress(String),
}

/// The signing manager's view of the UI: a thin sender into the Iced
/// subscription channel.
pub struct NativeUICallback {
    tx: UnboundedSender<UiEvent>,
}

impl NativeUICallback {
    pub fn new(tx: UnboundedSender<UiEvent>) -> Self {
        Self { tx }
    }

    fn send(&self, event: UiEvent) {
        // The receiver lives for the whole app lifetime; a send error
        // only happens during shutdown, so dropping it is fine.
        let _ = self.tx.send(event);
    }
}

#[async_trait]
impl UICallback for NativeUICallback {
    // Wallets, sessions, connection and DKG progress come from the runner's
    // model (core_adapter's on_sync), not from these legacy manager hooks.
    async fn update_connection_status(&self, _websocket: bool, _webrtc: bool) {}
    async fn update_mesh_connections(&self, _connections: Vec<ConnectionInfo>) {}
    async fn update_operation_mode(&self, _mode: OperationMode) {}
    async fn update_wallets(&self, _wallets: Vec<WalletInfo>) {}
    async fn update_active_wallet(&self, _index: usize) {}
    async fn update_available_sessions(&self, _sessions: Vec<SessionInfo>) {}
    async fn update_active_session(&self, _session: Option<SessionInfo>) {}
    async fn update_dkg_status(&self, _active: bool, _round: u8, _progress: f32) {}
    async fn update_dkg_participants(&self, _participants: Vec<ParticipantInfo>) {}
    async fn update_offline_status(&self, _enabled: bool, _sd_card_detected: bool) {}
    async fn update_sd_operations(&self, _operations: Vec<SDCardOperation>) {}

    async fn update_signing_request(&self, request: Option<SigningRequest>) {
        self.send(UiEvent::SigningRequest(request));
    }

    async fn update_signing_state(&self, state: SigningState) {
        self.send(UiEvent::SigningState(state));
    }

    async fn update_signing_complete(&self, signature_hex: String) {
        self.send(UiEvent::SigningComplete(signature_hex));
    }

    async fn show_message(&self, message: String, is_error: bool) {
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        let prefix = if is_error { "[ERROR]" } else { "[INFO]" };
        let log_line = format!("{timestamp} {prefix} {message}");
        self.send(UiEvent::Message {
            log_line,
            status: message,
            is_error,
        });
    }

    async fn show_progress(&self, title: String, progress: f32) {
        let text = format!("{}: {:.0}%", title, progress * 100.0);
        self.send(UiEvent::Progress(text));
    }

    async fn request_confirmation(&self, _message: String) -> bool {
        // Only reachable from manager flows the desktop no longer exposes.
        true
    }
}
