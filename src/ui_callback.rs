//! `UICallback` implementation for the native Iced UI.
//!
//! The previous Slint version posted closures onto the Slint event loop
//! via `Weak<MainWindow>` + `slint::invoke_from_event_loop` (needed
//! because `MainWindow` is `!Send`). Iced has no equivalent "poke the
//! widget tree from another thread" surface — instead it consumes a
//! `Subscription` that yields `Message`s.
//!
//! So the bridge is just a `tokio::sync::mpsc::UnboundedSender<UiEvent>`:
//! the async core managers call the `UICallback` methods, each method
//! serialises its arguments into a `UiEvent` and pushes it down the
//! channel; the Iced app's subscription drains the matching receiver and
//! turns every `UiEvent` into a `Message::Ui(..)` handled in `update`.
//! This is the canonical Iced pattern for external events and is both
//! `Send`-clean and free of the `!Send` upgrade dance.

use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use starlab_client::core::{
    ConnectionInfo, OperationMode, ParticipantInfo, SDCardOperation, SessionInfo, SigningRequest,
    SigningState, UICallback, WalletInfo,
};

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

/// One UI-state mutation pushed from the async core into the Iced app.
///
/// Each variant maps 1:1 onto a `UICallback` trait method. The Iced
/// `update` fn applies these onto its `State` model.
#[derive(Debug, Clone)]
pub enum UiEvent {
    ConnectionStatus { websocket: bool, webrtc: bool },
    MeshConnections(Vec<ConnectionInfo>),
    OperationMode(OperationMode),
    Wallets(Vec<WalletInfo>),
    /// Multi-chain wallet list (grouped by id) — drives the wallet selector.
    WalletsRich(Vec<WalletView>),
    ActiveWallet(usize),
    AvailableSessions(Vec<SessionInfo>),
    ActiveSession(Option<SessionInfo>),
    DkgStatus { active: bool, round: u8, progress: f32 },
    DkgParticipants(Vec<ParticipantInfo>),
    OfflineStatus { enabled: bool, sd_card_detected: bool },
    SdOperations(Vec<SDCardOperation>),
    SigningRequest(Option<SigningRequest>),
    SigningState(SigningState),
    SigningComplete(String),
    /// `(formatted_log_line, status_message, is_error)`.
    Message { log_line: String, status: String, is_error: bool },
    /// `(status_message)` for progress updates.
    Progress(String),
}

/// Native UI callback implementation: a thin sender into the Iced
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
    async fn update_connection_status(&self, websocket: bool, webrtc: bool) {
        self.send(UiEvent::ConnectionStatus { websocket, webrtc });
    }

    async fn update_mesh_connections(&self, connections: Vec<ConnectionInfo>) {
        self.send(UiEvent::MeshConnections(connections));
    }

    async fn update_operation_mode(&self, mode: OperationMode) {
        self.send(UiEvent::OperationMode(mode));
    }

    async fn update_wallets(&self, wallets: Vec<WalletInfo>) {
        self.send(UiEvent::Wallets(wallets));
    }

    async fn update_active_wallet(&self, index: usize) {
        self.send(UiEvent::ActiveWallet(index));
    }

    async fn update_available_sessions(&self, sessions: Vec<SessionInfo>) {
        self.send(UiEvent::AvailableSessions(sessions));
    }

    async fn update_active_session(&self, session: Option<SessionInfo>) {
        self.send(UiEvent::ActiveSession(session));
    }

    async fn update_dkg_status(&self, active: bool, round: u8, progress: f32) {
        self.send(UiEvent::DkgStatus { active, round, progress });
    }

    async fn update_dkg_participants(&self, participants: Vec<ParticipantInfo>) {
        self.send(UiEvent::DkgParticipants(participants));
    }

    async fn update_offline_status(&self, enabled: bool, sd_card_detected: bool) {
        self.send(UiEvent::OfflineStatus { enabled, sd_card_detected });
    }

    async fn update_sd_operations(&self, operations: Vec<SDCardOperation>) {
        self.send(UiEvent::SdOperations(operations));
    }

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
        // Auto-confirm, matching the prior Slint behaviour. A future
        // pass can route this through a oneshot channel + a modal
        // Message so the user actually decides.
        // TODO(iced): surface a real confirmation modal.
        true
    }
}
