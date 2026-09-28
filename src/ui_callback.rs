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

/// A wallet grouped across curves for display: one entry per `wallet_id`, with
/// the group key of every curve it holds (secp256k1 → Ethereum + Bitcoin;
/// ed25519 → Solana + Sui; a unified wallet has both curves). Addresses are
/// NOT carried here — the view derives them per BIP-44 account from the group
/// key via `starlab_core::accounts` (public-only, cheap), so switching
/// accounts is a pure `State` change with no async round-trip. The root
/// group-key address is never shown: account 0 is the default identity.
#[derive(Debug, Clone)]
pub struct WalletView {
    pub id: String,
    pub name: String,
    pub threshold: String,
    /// (curve_type, group_public_key_hex) — one entry per curve this wallet
    /// holds ("secp256k1" / "ed25519"; a unified wallet has both).
    pub keys: Vec<(String, String)>,
}

/// A session announced in the room, as the desktop shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Invite {
    pub id: String,
    pub proposer: String,
    /// Devices that have joined so far (the proposer included).
    pub participants: Vec<String>,
    pub threshold: u16,
    pub total: u16,
    pub kind: InviteKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InviteKind {
    /// A new shared wallet (DKG) looking for devices.
    Wallet,
    /// A request to co-sign `message_hex` with the account wallet `wallet_id`.
    Signing {
        wallet_id: String,
        message_hex: String,
    },
}

/// One UI-state mutation pushed from the async core into the Iced app.
#[derive(Debug, Clone)]
pub enum UiEvent {
    Connected(bool),
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
    // The desktop signs in one step (request + approve), so the manager's
    // "confirm this request" hook has nothing to show.
    async fn update_signing_request(&self, _request: Option<SigningRequest>) {}

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
