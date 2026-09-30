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

use crate::wallet_view::WalletView;

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
    /// FROST DKG progress (`active`, `round`, `progress`), and whether the
    /// FROST part is done and the wallet's threshold-ECDSA (Ethereum) key
    /// ceremony runs (`ecdsa_key`).
    DkgStatus {
        active: bool,
        round: u8,
        progress: f32,
        ecdsa_key: bool,
    },
    /// The running ECDSA key ceremony waits for this device's safe primes
    /// (the engine's notice when its DKG worker has to wait).
    EcdsaWaitingForPrimes,
    /// The runner has a wallet ceremony open — as creator (invite announced)
    /// or joiner (joined, waiting for DKG). Cleared on finalize/cancel.
    CeremonyOpen(bool),
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
