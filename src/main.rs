//! Starlab Desktop — an Iced GUI over the starlab-mpc engine.
//!
//! Elm architecture: [`State`] is the model, [`Message`]s are handled in
//! [`State::update`], and `view` renders the model. The async core pushes
//! state as [`UiEvent`]s over an mpsc channel that a [`Subscription`] turns
//! into [`Message::Ui`].
//!
//! Layout: the left column holds what the other screens depend on — the
//! network (server + room) and the wallets (plus key-share backup). The
//! main area follows the user's flow: set up a wallet, sign with it, and an
//! activity log. Anything that needs attention right now (a running wallet
//! setup, a peer's signature request) is pinned above the tabs.

mod core_adapter;
mod ui;
mod ui_callback;

use std::sync::{Arc, Mutex as StdMutex};

use iced::futures::stream;
use iced::{Subscription, Task, Theme};

use core_adapter::{CoreAdapter, DEFAULT_THRESHOLD, DEFAULT_TOTAL};
use starlab_client::core::{SigningRequest, SigningState};
use starlab_client::protocal::ecdsa::DkgPhase;
use ui_callback::{EcdsaSetup, Invite, UiEvent, WalletView};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    iced::application(State::new, State::update, State::view)
        .title("Starlab Desktop")
        .window_size((1120.0, 680.0))
        .settings(iced::Settings {
            default_text_size: 14.0.into(),
            ..iced::Settings::default()
        })
        .theme(State::theme)
        .subscription(State::subscription)
        .run()
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Main-area tabs, in the order a user needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Setup,
    Sign,
    Activity,
    Connection,
    Backup,
}

/// Every password field sits next to the action that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordField {
    /// New password for the share a created wallet produces (+ confirmation).
    Create,
    CreateConfirm,
    /// New password for the share a joined wallet produces (+ confirmation).
    Join,
    JoinConfirm,
    /// Unlocks this device's share to sign or co-sign.
    Unlock,
    /// Encrypts an exported share / decrypts an imported one.
    Backup,
}

#[derive(Debug, Clone, Default)]
struct Passwords {
    create: String,
    create_confirm: String,
    join: String,
    join_confirm: String,
    unlock: String,
    backup: String,
}

impl Passwords {
    fn get_mut(&mut self, field: PasswordField) -> &mut String {
        match field {
            PasswordField::Create => &mut self.create,
            PasswordField::CreateConfirm => &mut self.create_confirm,
            PasswordField::Join => &mut self.join,
            PasswordField::JoinConfirm => &mut self.join_confirm,
            PasswordField::Unlock => &mut self.unlock,
            PasswordField::Backup => &mut self.backup,
        }
    }
}

/// An action whose async call is still in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAction {
    ImportShare,
    ExportShare,
    CreateWallet,
    JoinWallet,
    CoSign,
    Sign,
}

#[derive(Debug, Clone)]
pub enum Message {
    Ui(UiEvent),
    TabSelected(Tab),
    ToggleActivityDetails,
    ToggleSigningDetails,

    // Network
    ServerUrlChanged(String),
    RoomChanged(String),
    NewRoom,
    CopyRoom,
    Connect,

    // Wallets
    WalletSelected(usize),
    /// Switch the displayed BIP-44 account — addresses are re-derived
    /// locally in the view from the wallet's group key (no async hop).
    SelectAccount(u32),
    /// Reveal one more account in the picker (the `+` button).
    AddAccount,
    PasswordChanged(PasswordField, String),
    ImportShare,
    ExportShare,

    // Wallet setup
    WalletNameChanged(String),
    InviteIdChanged(String),
    CreateWallet,
    JoinWallet,
    CopyInvite,
    CancelSetup,

    // Signing
    SignChainSelected(&'static str),
    SignHexChanged(String),
    Sign,
    CopySignature,
    /// Co-sign a peer's signing request (its request id).
    ApproveSignatureRequest(String),
    RejectSignatureRequest(String),
    /// Close a peer's request whose ceremony failed.
    DismissSigning,

    /// Result of an async core action; failures surface in the status bar.
    ActionDone(Result<(), String>),

    /// Tab / Shift+Tab: move keyboard focus between inputs.
    FocusNext,
    FocusPrevious,
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Launch configuration. Env vars keep scripted launches working.
struct Config {
    device_id: String,
    keystore_path: String,
    server_url: String,
    room: String,
    curve: String,
}

impl Config {
    fn from_env() -> Self {
        let server_input =
            std::env::var("MPC_SIGNAL_SERVER").unwrap_or_else(|_| "wss://panda.qzz.io".to_string());
        let (server_url, room_from_url) = split_signal_room(&server_input);
        Self {
            device_id: std::env::var("MPC_DEVICE_ID")
                .unwrap_or_else(|_| "native-node-001".to_string()),
            // Keystore lives alongside the TUI's (~/.frost_keystore).
            keystore_path: std::env::var("MPC_KEYSTORE_PATH")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .unwrap_or_else(|| {
                    format!(
                        "{}/.frost_keystore",
                        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                    )
                }),
            server_url,
            room: std::env::var("MPC_ROOM")
                .ok()
                .filter(|room| !room.trim().is_empty())
                .or(room_from_url)
                .unwrap_or_else(generate_room_id),
            curve: std::env::var("MPC_CURVE").unwrap_or_else(|_| "secp256k1".to_string()),
        }
    }
}

pub struct State {
    adapter: Arc<CoreAdapter>,
    device_id: String,
    /// The curve this instance signs on: `"secp256k1"` or `"ed25519"`.
    signing_curve: &'static str,

    // Network
    server_url: String,
    room: String,
    connected: bool,
    /// Peers with an open WebRTC data channel to this device.
    peers: usize,
    /// URL of the last connect request. When the fields no longer match it,
    /// the network card offers a reconnect.
    connected_url: Option<String>,

    // Wallets
    wallets: Vec<WalletView>,
    active_wallet_index: usize,
    /// The BIP-44 account used for display and signing (the root group-key
    /// address is never shown).
    selected_account: u32,
    /// Highest account index the picker offers; `+` reveals one more.
    max_account: u32,
    passwords: Passwords,

    // Sessions and the wallet-setup ceremony
    invites: Vec<Invite>,
    active_session: Option<Invite>,
    ceremony_open: bool,
    /// FROST done, the Ethereum (threshold-ECDSA) key is being made.
    ecdsa_keygen: bool,
    ecdsa_phase: Option<DkgPhase>,
    /// This device's safe-prime generator (the next wallet's ECDSA setup).
    ecdsa_setup: EcdsaSetup,
    dkg_active: bool,
    dkg_round: u8,
    dkg_progress: f32,

    // Signing
    /// The signing manager's request: ours while we sign, or a peer's
    /// (`session_id` set) waiting for this device.
    signing_request: Option<SigningRequest>,
    sign_chain: &'static str,
    sign_hex: String,
    signing_state: SigningState,
    last_signature: String,
    /// What the pending/last own signing was for, to label and verify the
    /// signature when it arrives.
    last_signed: Option<SignedFor>,

    // UI
    active_tab: Tab,
    show_activity_details: bool,
    show_signing_details: bool,
    wallet_name: String,
    invite_id: String,
    pending_action: Option<PendingAction>,
    status: String,
    status_is_error: bool,
    log_messages: Vec<String>,
}

impl State {
    fn new() -> (Self, Task<Message>) {
        Self::with_config(Config::from_env())
    }

    fn with_config(config: Config) -> (Self, Task<Message>) {
        // Build the core → UI bridge channel. The sender goes into the
        // CoreAdapter; the receiver is stashed for the subscription to pull
        // out exactly once.
        let (ui_tx, ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
        BRIDGE_RX.lock().expect("bridge mutex").replace(ui_rx);

        let signing_curve = if config.curve == "ed25519" {
            "ed25519"
        } else {
            "secp256k1"
        };
        let adapter = Arc::new(CoreAdapter::new(
            ui_tx,
            config.device_id.clone(),
            config.keystore_path,
            signal_url_with_room(&config.server_url, &config.room),
            config.curve,
        ));

        let state = State {
            adapter,
            device_id: config.device_id,
            signing_curve,
            server_url: config.server_url,
            room: config.room,
            connected: false,
            peers: 0,
            connected_url: None,
            wallets: Vec::new(),
            active_wallet_index: 0,
            selected_account: 0,
            max_account: 2,
            passwords: Passwords::default(),
            invites: Vec::new(),
            active_session: None,
            ceremony_open: false,
            ecdsa_keygen: false,
            ecdsa_phase: None,
            ecdsa_setup: if signing_curve == "ed25519" {
                EcdsaSetup::NotNeeded
            } else {
                EcdsaSetup::Preparing { elapsed_secs: 0 }
            },
            dkg_active: false,
            dkg_round: 0,
            dkg_progress: 0.0,
            signing_request: None,
            sign_chain: device_chains(signing_curve)[0].0,
            sign_hex: String::new(),
            signing_state: SigningState::Idle,
            last_signature: String::new(),
            last_signed: None,
            active_tab: Tab::Setup,
            show_activity_details: false,
            show_signing_details: false,
            wallet_name: String::new(),
            invite_id: String::new(),
            pending_action: None,
            status: "Ready".to_string(),
            status_is_error: false,
            log_messages: Vec::new(),
        };

        // A wallet should reach its network immediately.
        (state, Task::done(Message::Connect))
    }

    fn theme(&self) -> Theme {
        ui::theme::desktop_theme()
    }

    fn subscription(&self) -> Subscription<Message> {
        // `Subscription::run` identifies the subscription by the worker fn,
        // so it's spawned exactly once for the app's life.
        Subscription::batch([
            Subscription::run(ui_bridge),
            // Iced doesn't move focus on Tab by itself.
            iced::keyboard::listen().filter_map(tab_focus),
        ])
    }

    // -- Update ---------------------------------------------------------

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Ui(event) => {
                self.apply_ui_event(event);
                Task::none()
            }
            Message::ToggleSigningDetails => {
                self.show_signing_details = !self.show_signing_details;
                Task::none()
            }
            Message::ToggleActivityDetails => {
                self.show_activity_details = !self.show_activity_details;
                Task::none()
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                Task::none()
            }

            Message::ServerUrlChanged(v) => {
                let (base, room) = split_signal_room(&v);
                self.server_url = base;
                // split_signal_room returns None for a missing or empty room=,
                // so a URL still being typed keeps the previously-set room.
                if let Some(room) = room {
                    self.room = room;
                }
                Task::none()
            }
            Message::RoomChanged(v) => {
                self.room = normalize_room_id(&v);
                Task::none()
            }
            Message::NewRoom => {
                self.room = generate_room_id();
                Task::none()
            }
            Message::CopyRoom => {
                self.set_status("Room ID copied");
                iced::clipboard::write(self.room.clone())
            }
            Message::Connect => {
                if !self.can_connect() {
                    return Task::none();
                }
                if self.room.trim().is_empty() {
                    self.room = generate_room_id();
                }
                let url = self.signal_url();
                self.connected_url = Some(url.clone());
                self.set_status("Connecting to the network");
                let adapter = self.adapter.clone();
                action(async move { adapter.connect_websocket(url).await })
            }

            Message::WalletSelected(i) => {
                self.active_wallet_index = i;
                Task::none()
            }
            Message::SelectAccount(i) => {
                self.selected_account = i;
                Task::none()
            }
            Message::AddAccount => {
                // Reveal + jump straight to the new account.
                self.max_account += 1;
                self.selected_account = self.max_account;
                Task::none()
            }
            Message::PasswordChanged(field, v) => {
                *self.passwords.get_mut(field) = v;
                Task::none()
            }
            Message::ImportShare => {
                if self.import_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let password = self.passwords.backup.clone();
                self.pending_action = Some(PendingAction::ImportShare);
                self.set_status("Importing a key share");
                action(async move { adapter.import_share(password).await })
            }
            Message::ExportShare => {
                let Some((wallet_id, curves)) = self.export_target() else {
                    return Task::none();
                };
                if self.export_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let password = self.passwords.backup.clone();
                self.pending_action = Some(PendingAction::ExportShare);
                self.set_status("Exporting the key shares");
                action(async move { adapter.export_shares(wallet_id, curves, password).await })
            }

            Message::WalletNameChanged(v) => {
                self.wallet_name = v;
                Task::none()
            }
            Message::InviteIdChanged(v) => {
                self.invite_id = v;
                Task::none()
            }
            Message::CreateWallet => {
                if self.create_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let name = self.wallet_name.clone();
                let password = std::mem::take(&mut self.passwords.create);
                self.passwords.create_confirm.clear();
                self.pending_action = Some(PendingAction::CreateWallet);
                self.set_status("Creating the wallet invite");
                action(async move { adapter.create_wallet(name, password).await })
            }
            Message::JoinWallet => {
                if self.join_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let id = self.invite_id.trim().to_string();
                let password = std::mem::take(&mut self.passwords.join);
                self.passwords.join_confirm.clear();
                self.pending_action = Some(PendingAction::JoinWallet);
                self.set_status("Joining the wallet");
                action(async move { adapter.join_session(id, password).await })
            }
            Message::CopyInvite => {
                let Some(id) = self.own_invite().map(|invite| invite.id.clone()) else {
                    return Task::none();
                };
                self.set_status("Invite ID copied");
                iced::clipboard::write(id)
            }
            Message::CancelSetup => {
                self.set_status("Wallet setup cancelled");
                let adapter = self.adapter.clone();
                action(async move { adapter.cancel_ceremony().await })
            }

            Message::SignChainSelected(chain) => {
                self.sign_chain = chain;
                Task::none()
            }
            Message::SignHexChanged(v) => {
                self.sign_hex = v;
                Task::none()
            }
            Message::Sign => {
                let Some(wallet_id) = self.signing_wallet_id() else {
                    return Task::none();
                };
                if self.sign_blocker().is_some() || self.pending_action.is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let chain = self.sign_chain.to_string();
                let (hex, password) = (
                    self.sign_hex.trim().to_string(),
                    self.passwords.unlock.clone(),
                );
                self.last_signed = self.signing_address().map(|(address, _)| SignedFor {
                    chain: self.sign_chain,
                    message_hex: hex.clone(),
                    prehashed: false,
                    address,
                    cosigned: false,
                });
                self.pending_action = Some(PendingAction::Sign);
                self.last_signature.clear();
                self.set_status(
                    "Signature requested — approve it on another device of this wallet",
                );
                action(async move { adapter.sign(wallet_id, chain, hex, password).await })
            }
            Message::CopySignature => {
                self.set_status("Signature copied");
                iced::clipboard::write(self.last_signature.clone())
            }
            Message::ApproveSignatureRequest(request_id) => {
                if self.approve_blocker().is_some() {
                    return Task::none();
                }
                self.last_signed = self
                    .signing_request
                    .as_ref()
                    .filter(|r| r.id == request_id)
                    .and_then(|r| self.cosign_target(r));
                self.last_signature.clear();
                let adapter = self.adapter.clone();
                let password = self.passwords.unlock.clone();
                self.pending_action = Some(PendingAction::CoSign);
                self.set_status("Co-signing");
                action(async move { adapter.approve_signing(request_id, password).await })
            }
            Message::RejectSignatureRequest(request_id) => {
                self.set_status("Signature request declined");
                let adapter = self.adapter.clone();
                action(async move { adapter.reject_signing(request_id).await })
            }
            Message::DismissSigning => {
                let adapter = self.adapter.clone();
                action(async move { adapter.dismiss_signing().await })
            }

            Message::FocusNext => iced::widget::operation::focus_next(),
            Message::FocusPrevious => iced::widget::operation::focus_previous(),

            Message::ActionDone(result) => {
                // Create/join only queue a message to the runner; from here on
                // `ceremony_open` / `dkg_active` track the setup.
                self.pending_action = None;
                if let Err(e) = result {
                    tracing::warn!("action failed: {e}");
                    self.push_log(format!("[ERROR] {e}"));
                    self.status = e;
                    self.status_is_error = true;
                }
                Task::none()
            }
        }
    }

    /// Apply a single core event onto the model.
    fn apply_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Connected(connected) => {
                if connected && !self.connected {
                    self.set_status("Connected to the network");
                }
                self.connected = connected;
            }
            UiEvent::ConnectionFailed => {
                self.connected = false;
                self.connected_url = None;
                self.set_status(
                    "Could not connect. Check the signal server and room, then try Connect again.",
                );
                self.status_is_error = true;
            }
            UiEvent::Peers(peers) => self.peers = peers,
            UiEvent::Wallets(wallets) => {
                // A new wallet (startup load or a finished setup) → go sign.
                if wallets.len() > self.wallets.len() && self.active_tab == Tab::Setup {
                    self.active_tab = Tab::Sign;
                }
                self.wallets = wallets;
                if self.active_wallet_index >= self.wallets.len() {
                    self.active_wallet_index = 0;
                }
            }
            UiEvent::Invites(invites) => self.invites = invites,
            UiEvent::ActiveSession(session) => self.active_session = session,
            UiEvent::DkgStatus {
                active,
                round,
                progress,
            } => {
                self.dkg_active = active;
                self.dkg_round = round;
                self.dkg_progress = progress;
            }
            UiEvent::CeremonyOpen(open) => self.ceremony_open = open,
            UiEvent::EcdsaKeygen { running, phase } => {
                self.ecdsa_keygen = running;
                self.ecdsa_phase = phase;
            }
            UiEvent::EcdsaSetup(setup) => self.ecdsa_setup = setup,
            UiEvent::SigningRequest(request) => self.signing_request = request,
            UiEvent::SigningState(state) => self.signing_state = state,
            UiEvent::SigningComplete(signature) => {
                // Shown (and verified) either way; a co-signer's copy is
                // labelled as the requesting device's signature.
                let cosigned = self.last_signed.as_ref().is_some_and(|s| s.cosigned);
                self.last_signature = signature;
                self.set_status(if cosigned {
                    "Co-signed — the requesting device has the signature too"
                } else {
                    "Signature ready"
                });
            }
            UiEvent::Message {
                log_line,
                status,
                is_error,
            } => {
                self.push_log(log_line);
                self.status = status;
                self.status_is_error = is_error;
            }
            UiEvent::Progress(status) => self.set_status(&status),
        }
    }

    fn set_status(&mut self, status: &str) {
        self.status = status.to_string();
        self.status_is_error = false;
    }

    fn push_log(&mut self, line: String) {
        self.log_messages.push(line);
        let overflow = self.log_messages.len().saturating_sub(100);
        if overflow > 0 {
            self.log_messages.drain(0..overflow);
        }
    }

    // -- Derived state ----------------------------------------------------

    fn signal_url(&self) -> String {
        signal_url_with_room(&self.server_url, &self.room)
    }

    /// Server or room edited since the last connect (or never connected).
    fn network_changed(&self) -> bool {
        self.connected_url.as_deref() != Some(self.signal_url().as_str())
    }

    /// Switching rooms mid-setup would strand the ceremony.
    fn can_connect(&self) -> bool {
        !(self.connected && self.wallet_busy())
    }

    /// A wallet setup is queued, or the runner still has a ceremony open.
    /// `pending_action` clears as soon as Create/Join is sent, so without
    /// `ceremony_open` the buttons would re-enable while waiting for peers
    /// and a second click would start a second ceremony.
    fn wallet_busy(&self) -> bool {
        matches!(
            self.pending_action,
            Some(PendingAction::CreateWallet | PendingAction::JoinWallet)
        ) || self.dkg_active
            || self.ceremony_open
    }

    fn own_invite(&self) -> Option<&Invite> {
        own_invite(&self.device_id, self.active_session.as_ref())
    }

    /// Why "Create wallet" is disabled, if it is.
    fn create_blocker(&self) -> Option<&'static str> {
        self.setup_blocker().or_else(|| {
            new_password_problem(&self.passwords.create, &self.passwords.create_confirm)
        })
    }

    /// Why "Join wallet" is disabled, if it is.
    fn join_blocker(&self) -> Option<&'static str> {
        self.setup_blocker()
            .or_else(|| {
                self.invite_id
                    .trim()
                    .is_empty()
                    .then_some("Pick an invite or paste its ID.")
            })
            .or_else(|| new_password_problem(&self.passwords.join, &self.passwords.join_confirm))
    }

    /// What blocks both Create and Join, if anything.
    fn setup_blocker(&self) -> Option<&'static str> {
        if !self.connected {
            Some("Connect to the network first.")
        } else if self.wallet_busy() {
            Some("A wallet setup is already in progress.")
        } else {
            None
        }
    }

    /// Why "Import key share…" is disabled, if it is.
    fn import_blocker(&self) -> Option<&'static str> {
        if self.pending_action.is_some() {
            Some("Another action is in progress.")
        } else if self.passwords.backup.is_empty() {
            Some("Enter the password the key share was exported with.")
        } else {
            None
        }
    }

    /// Why "Export key share…" is disabled, if it is.
    fn export_blocker(&self) -> Option<&'static str> {
        if self.export_target().is_none() {
            Some("Select a wallet to export.")
        } else if self.pending_action.is_some() {
            Some("Another action is in progress.")
        } else {
            password_problem(&self.passwords.backup)
        }
    }

    /// `(wallet id, curves)` "Export key share…" writes: every key of the
    /// selected wallet (a secp256k1 wallet has a Taproot and an ECDSA key —
    /// losing the ECDSA file would lose the Ethereum account).
    fn export_target(&self) -> Option<(String, Vec<String>)> {
        let wallet = self.active_wallet()?;
        let curves: Vec<String> = wallet.keys.iter().map(|(c, _)| c.clone()).collect();
        (!curves.is_empty()).then(|| (wallet.id.clone(), curves))
    }

    /// Why "Request signature" is disabled, if it is.
    fn sign_blocker(&self) -> Option<&'static str> {
        if self.signing_wallet_id().is_none() {
            Some("This wallet has no key for this chain on this device.")
        } else if !self.connected {
            Some("Connect to the network first.")
        } else if self.passwords.unlock.is_empty() {
            Some("Enter the wallet password.")
        } else if self.sign_hex.trim().is_empty() {
            Some("Enter the message to sign.")
        } else if hex::decode(self.sign_hex.trim().trim_start_matches("0x")).is_err() {
            // The engine would reject it only after the ceremony times out.
            Some("The message must be hex bytes.")
        } else {
            None
        }
    }

    /// Why a peer's signature request can't be approved yet, if it can't.
    fn approve_blocker(&self) -> Option<&'static str> {
        if !self.connected {
            Some("Connect to the network first.")
        } else if self.passwords.unlock.is_empty() {
            Some("Enter the wallet password to approve.")
        } else if self.pending_action.is_some() {
            Some("Another action is in progress.")
        } else {
            None
        }
    }

    fn active_wallet(&self) -> Option<&WalletView> {
        self.wallets.get(self.active_wallet_index)
    }

    /// The account wallet signing uses: `<root>-<chain>-<account>`. The
    /// engine signs an Ethereum account with the wallet's threshold-ECDSA
    /// key and a Bitcoin account with its FROST Taproot key.
    fn signing_wallet_id(&self) -> Option<String> {
        let wallet = self.active_wallet()?;
        wallet_has_chain(wallet, self.sign_chain).then(|| {
            format!(
                "{}-{}-{}",
                wallet.id, self.sign_chain, self.selected_account
            )
        })
    }

    /// What a peer's request asks this device to co-sign: its account's
    /// address, and the digest the ceremony signs (an Ethereum request
    /// carries the EIP-191 hash, not the text).
    fn cosign_target(&self, request: &SigningRequest) -> Option<SignedFor> {
        let (root, chain, account) =
            starlab_core::accounts::parse_child_wallet_id(&request.wallet_id)?;
        let wallet = self.wallets.iter().find(|w| w.id == root)?;
        let chain = device_chains(self.signing_curve)
            .into_iter()
            .find(|(key, _)| *key == chain)?
            .0;
        let (address, _) = account_address(wallet, chain, account)?;
        Some(SignedFor {
            chain,
            message_hex: request.message_hex.clone(),
            prehashed: true,
            address,
            cosigned: true,
        })
    }

    /// `(address, derivation path)` of the signing account on the chosen chain.
    fn signing_address(&self) -> Option<(String, String)> {
        account_address(
            self.active_wallet()?,
            self.sign_chain,
            self.selected_account,
        )
    }

    /// "Treasury · Ethereum · Account 0" for an account wallet id.
    fn describe_account_wallet(&self, wallet_id: &str) -> String {
        let Some((root, chain, account)) = starlab_core::accounts::parse_child_wallet_id(wallet_id)
        else {
            return wallet_id.to_string();
        };
        let name = self
            .wallets
            .iter()
            .find(|w| w.id == root)
            .map_or(root, |w| w.name.as_str());
        format!("{name} · {} · Account {account}", chain_label(chain))
    }

    // -- View -----------------------------------------------------------
}

/// What our own signing request was for: the chain, the message as typed
/// (hex) and the account address the signature must check out against.
#[derive(Debug, Clone, PartialEq)]
struct SignedFor {
    chain: &'static str,
    /// The message as typed (hex) — or, for a peer's request this device
    /// co-signed, the 32-byte digest the ceremony signed (`prehashed`).
    message_hex: String,
    prehashed: bool,
    address: String,
    /// A peer's request this device co-signed (not our own signing).
    cosigned: bool,
}

/// The chains this device signs: a secp256k1 device signs Ethereum with the
/// wallet's threshold-ECDSA key and Bitcoin with its FROST Taproot key; an
/// ed25519 device signs Solana and Sui.
fn device_chains(signing_curve: &str) -> Vec<(&'static str, &'static str)> {
    use starlab_core::accounts::chains_for_curve;
    if signing_curve == "ed25519" {
        chains_for_curve("ed25519").to_vec()
    } else {
        chains_for_curve(starlab_core::ecdsa::ECDSA_CURVE)
            .iter()
            .chain(chains_for_curve("secp256k1"))
            .copied()
            .collect()
    }
}

/// Display name of a chain key ("ethereum" → "Ethereum").
fn chain_label(chain: &str) -> &str {
    ["ed25519", "secp256k1", starlab_core::ecdsa::ECDSA_CURVE]
        .iter()
        .flat_map(|c| starlab_core::accounts::chains_for_curve(c))
        .find(|(key, _)| *key == chain)
        .map_or(chain, |(_, label)| *label)
}

/// The wallet holds the key that signs `chain` (Ethereum → its ECDSA key).
fn wallet_has_chain(wallet: &WalletView, chain: &str) -> bool {
    starlab_core::accounts::curve_for_chain(chain)
        .is_some_and(|curve| wallet.keys.iter().any(|(c, _)| c == curve))
}

/// `(address, path)` of `account` on `chain`, derived public-only from the
/// wallet key that signs that chain.
fn account_address(wallet: &WalletView, chain: &str, account: u32) -> Option<(String, String)> {
    let curve = starlab_core::accounts::curve_for_chain(chain)?;
    let (_, group_key) = wallet.keys.iter().find(|(c, _)| c == curve)?;
    let group_key = hex::decode(group_key).ok()?;
    starlab_core::accounts::account_addresses(curve, &group_key, account)
        .ok()?
        .into_iter()
        .find(|(name, _, _)| name.eq_ignore_ascii_case(chain))
        .map(|(_, path, address)| (address, path))
}

/// How the signature panel describes a finished signature.
#[derive(Debug, Clone, PartialEq)]
struct SignatureSummary {
    label: &'static str,
    /// Extra lines, e.g. the r / s / v of an ECDSA signature.
    parts: Vec<String>,
    verified: bool,
    verification: String,
}

/// Name, split and verify our signature (`0x…` hex) for what was signed:
/// Ethereum → 65-byte `r ‖ s ‖ v`, checked with `ecrecover` over the EIP-191
/// hash against the account address (what an EVM node checks); Bitcoin →
/// BIP-340 against the P2TR address. Other chains were checked under the
/// group key by the engine.
fn signature_summary(signed: Option<&SignedFor>, signature_hex: &str) -> SignatureSummary {
    let sig = hex::decode(signature_hex.trim_start_matches("0x")).unwrap_or_default();
    let message = signed
        .and_then(|s| hex::decode(s.message_hex.trim_start_matches("0x")).ok())
        .unwrap_or_default();
    match signed {
        Some(s) if s.chain == "ethereum" => {
            let mut parts = Vec::new();
            if let [rs @ .., v] = sig.as_slice()
                && rs.len() == 64
            {
                parts.push(format!("r = 0x{}", hex::encode(&rs[..32])));
                parts.push(format!("s = 0x{}", hex::encode(&rs[32..])));
                parts.push(format!("v = {v}"));
            }
            let prehash = if s.prehashed {
                message.clone()
            } else {
                starlab_client::utils::eth_helper::eip191_hash(&message).to_vec()
            };
            let (verified, verification) =
                match starlab_core::accounts::recover_ethereum_address(&prehash, &sig) {
                    Ok(addr) if addr.eq_ignore_ascii_case(&s.address) => (
                        true,
                        format!("Verified: ecrecover gives {addr} (this account)"),
                    ),
                    Ok(addr) => (
                        false,
                        format!(
                            "NOT verified: ecrecover gives {addr}, expected {}",
                            s.address
                        ),
                    ),
                    Err(e) => (false, format!("NOT verified: {e}")),
                };
            SignatureSummary {
                label: "ECDSA signature (r ‖ s ‖ v, 65 bytes) — ecrecover-compatible (EIP-191 personal_sign)",
                parts,
                verified,
                verification,
            }
        }
        Some(s) if s.chain == "bitcoin" => {
            let (verified, verification) = match starlab_core::accounts::verify_taproot_signature(
                &s.address, &message, &sig,
            ) {
                Ok(true) => (true, format!("Verified: BIP-340 valid for {}", s.address)),
                Ok(false) => (
                    false,
                    format!("NOT verified: BIP-340 check failed for {}", s.address),
                ),
                Err(e) => (false, format!("NOT verified: {e}")),
            };
            SignatureSummary {
                label: "BIP-340 Schnorr signature (64 bytes) — Taproot key-path spend",
                parts: Vec::new(),
                verified,
                verification,
            }
        }
        _ => SignatureSummary {
            label: "Signature",
            parts: Vec::new(),
            verified: true,
            verification: "Checked under the wallet's group key by the engine".to_string(),
        },
    }
}

/// The active Ethereum-key step; the next wallet's primes are independent.
fn ecdsa_keygen_detail(phase: Option<DkgPhase>, setup: EcdsaSetup) -> String {
    match (phase, setup) {
        (Some(DkgPhase::WaitingForPrimes), EcdsaSetup::Preparing { elapsed_secs }) => format!(
            "Preparing secure wallet setup ({} so far, usually 1-5 min). Keep every device online.",
            crate::ui_callback::format_elapsed(elapsed_secs)
        ),
        _ => "Creating your shared Ethereum key with the other devices (about a minute). Keep every device online.".to_string(),
    }
}

/// Our own invite: the session we proposed. A session we merely joined is
/// someone else's invite, so it is never shown as ours.
fn own_invite<'a>(device_id: &str, active: Option<&'a Invite>) -> Option<&'a Invite> {
    active.filter(|session| session.proposer == device_id)
}

/// New-wallet invites from other devices.
fn wallet_invites<'a>(device_id: &str, invites: &'a [Invite]) -> Vec<&'a Invite> {
    invites.iter().filter(|i| i.proposer != device_id).collect()
}

const MIN_PASSWORD_LEN: usize = 8;

/// Why `password` can't encrypt a key share, if it can't.
fn password_problem(password: &str) -> Option<&'static str> {
    if password.is_empty() {
        Some("Enter a password (at least 8 characters).")
    } else if password.chars().count() < MIN_PASSWORD_LEN {
        Some("The password must be at least 8 characters.")
    } else {
        None
    }
}

/// Why a new share password + its confirmation can't be used, if they can't.
fn new_password_problem(password: &str, confirm: &str) -> Option<&'static str> {
    password_problem(password)
        .or_else(|| (password != confirm).then_some("The passwords don't match."))
}

/// Password + confirmation for a new key share, side by side.
/// Tab moves focus forward, Shift+Tab back.
fn tab_focus(event: iced::keyboard::Event) -> Option<Message> {
    use iced::keyboard::{Event, Key, key::Named};
    match event {
        Event::KeyPressed {
            key: Key::Named(Named::Tab),
            modifiers,
            ..
        } => Some(if modifiers.shift() {
            Message::FocusPrevious
        } else {
            Message::FocusNext
        }),
        _ => None,
    }
}

fn signing_phase(state: &SigningState) -> &'static str {
    match state {
        SigningState::Aggregating => "Combining signatures…",
        SigningState::Complete => "Signed.",
        _ => "Waiting for another device of this wallet to approve…",
    }
}

fn generate_room_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn normalize_room_id(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect()
}

fn split_signal_room(input: &str) -> (String, Option<String>) {
    let url = input.trim();
    // Match `room=` only as a whole query key, not inside `chatroom=`.
    let room_key = url
        .match_indices("room=")
        .find(|&(pos, _)| pos == 0 || matches!(url.as_bytes().get(pos - 1), Some(b'?' | b'&')))
        .map(|(pos, _)| pos);
    let Some(room_key) = room_key else {
        return (url.to_string(), None);
    };

    let value_start = room_key + "room=".len();
    let value_end = url[value_start..]
        .find('&')
        .map(|offset| value_start + offset)
        .unwrap_or(url.len());
    let room = url[value_start..value_end].trim().to_string();

    let mut base = format!("{}{}", &url[..room_key], &url[value_end..]);
    while base.contains("?&") {
        base = base.replace("?&", "?");
    }
    // Removing a middle param leaves `&&` behind.
    while base.contains("&&") {
        base = base.replace("&&", "&");
    }
    while base.ends_with('?') || base.ends_with('&') {
        base.pop();
    }

    (base, (!room.is_empty()).then_some(room))
}

fn signal_url_with_room(base: &str, room: &str) -> String {
    let base = base.trim();
    let room = room.trim();
    if room.is_empty() || base.contains("room=") {
        return base.to_string();
    }

    if base.contains('?') {
        format!("{base}&room={room}")
    } else if base
        .split_once("://")
        .map(|(_, rest)| rest.contains('/'))
        .unwrap_or_else(|| base.contains('/'))
    {
        format!("{base}?room={room}")
    } else {
        format!("{base}/?room={room}")
    }
}

// ---------------------------------------------------------------------------
// The core → UI bridge
// ---------------------------------------------------------------------------

/// Holds the receiver end of the core → UI channel between `State::new`
/// (which creates it) and `ui_bridge` (the subscription worker that
/// consumes it). The subscription can't move a captured receiver into a
/// `'static` stream, so we stash it here and take it out on first run.
static BRIDGE_RX: StdMutex<Option<tokio::sync::mpsc::UnboundedReceiver<UiEvent>>> =
    StdMutex::new(None);

/// Subscription worker: turns the mpsc receiver into a `Stream<Message>`.
fn ui_bridge() -> impl iced::futures::Stream<Item = Message> {
    let rx = BRIDGE_RX
        .lock()
        .expect("bridge mutex")
        .take()
        .expect("ui_bridge started before State::new, or started twice");

    stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|event| (Message::Ui(event), rx))
    })
}

/// Wrap a fallible async core action into a `Task` that reports the
/// outcome via `Message::ActionDone`.
fn action<F>(fut: F) -> Task<Message>
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    Task::perform(fut, Message::ActionDone)
}

// ---------------------------------------------------------------------------
// Small view helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(id: &str, proposer: &str, participants: &[&str]) -> Invite {
        Invite {
            id: id.to_string(),
            proposer: proposer.to_string(),
            participants: participants.iter().map(|p| p.to_string()).collect(),
            threshold: 2,
            total: 3,
        }
    }

    /// A peer's request to co-sign with `wallet_id`.
    fn peer_request(wallet_id: &str, message_hex: &str) -> SigningRequest {
        SigningRequest {
            id: "req-1".to_string(),
            wallet_id: wallet_id.to_string(),
            message_hex: message_hex.to_string(),
            display_label: None,
            chain: "ethereum".to_string(),
            created_at: String::new(),
            session_id: Some("sig-1".to_string()),
        }
    }

    #[test]
    fn joined_session_is_not_shown_as_own_invite() {
        let joined = invite("s1", "peer", &["peer", "me"]);
        assert_eq!(own_invite("me", Some(&joined)), None);
    }

    #[test]
    fn created_session_is_shown_as_own_invite() {
        let created = invite("s1", "me", &["me"]);
        assert_eq!(own_invite("me", Some(&created)), Some(&created));
    }

    #[test]
    fn wallet_invites_exclude_our_own() {
        let invites = [
            invite("mine", "me", &["me"]),
            invite("theirs", "peer", &["peer"]),
        ];
        let ids: Vec<_> = wallet_invites("me", &invites)
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        assert_eq!(ids, ["theirs"]);
    }

    // ---- Headless UI tests (iced_test): real widgets, simulated clicks ----

    use iced_test::simulator;

    /// Each simulator brings up a GPU instance, and the Vulkan loader's
    /// driver scan isn't thread-safe: parallel UI tests segfault now and
    /// then. Every test that renders holds this lock.
    static RENDERER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn renderer_lock() -> std::sync::MutexGuard<'static, ()> {
        RENDERER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A State wired to a real engine runner on a throwaway keystore and an
    /// unreachable server — the view logic is what's under test.
    fn test_state() -> (State, std::path::PathBuf) {
        let keystore = std::env::temp_dir().join(format!("starlab-ui-{}", uuid::Uuid::new_v4()));
        let (state, _) = State::with_config(Config {
            device_id: "me".to_string(),
            keystore_path: keystore.to_string_lossy().into_owned(),
            server_url: "ws://127.0.0.1:9".to_string(),
            room: "3f6c1a52-9d0e-4b7a-8c21-5e4f0d9b7a13".to_string(),
            curve: "secp256k1".to_string(),
        });
        (state, keystore)
    }

    fn connected(state: &mut State) {
        state.connected = true;
        state.connected_url = Some(state.signal_url());
    }

    /// The secp256k1 generator G — any valid point works for address
    /// derivation; its Ethereum address is the well-known privkey-1 one.
    const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// A 2-of-3 secp256k1 wallet as the engine stores it: an ECDSA key
    /// (Ethereum) and a FROST Taproot key (Bitcoin), both = G here.
    fn with_wallet(state: &mut State) {
        state.wallets = vec![WalletView {
            id: "9c1f4e2ab37d".to_string(),
            name: "Treasury".to_string(),
            threshold: "2/3".to_string(),
            keys: vec![
                ("secp256k1-ecdsa".to_string(), G.to_string()),
                ("secp256k1".to_string(), G.to_string()),
            ],
        }];
    }

    fn clicked(state: &State, label: &str) -> Vec<Message> {
        let mut ui = simulator(state.view());
        ui.click(label).unwrap_or_else(|e| panic!("{label}: {e}"));
        ui.into_messages().collect()
    }

    #[tokio::test]
    async fn failed_connection_shows_error_and_allows_retry_without_editing_url() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.active_tab = Tab::Connection;
        state.connected_url = Some(state.signal_url());
        state.apply_ui_event(UiEvent::ConnectionFailed);
        assert!(!state.connected);
        assert!(state.status_is_error);
        assert!(state.status.contains("Could not connect"));
        assert!(state.network_changed());
        assert!(matches!(
            clicked(&state, "Connect").as_slice(),
            [Message::Connect]
        ));
        assert!(simulator(state.view()).find("Offline").is_ok());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn connection_and_backup_controls_are_reachable_from_navigation() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        assert!(simulator(state.view()).find("Signal server").is_err());
        assert!(simulator(state.view()).find("Key share password").is_err());
        assert!(matches!(
            clicked(&state, "Connection & devices").as_slice(),
            [Message::TabSelected(Tab::Connection)]
        ));
        let _ = state.update(Message::TabSelected(Tab::Connection));
        assert!(simulator(state.view()).find("Signal server").is_ok());
        assert!(matches!(
            clicked(&state, "Backup & restore").as_slice(),
            [Message::TabSelected(Tab::Backup)]
        ));
        let _ = state.update(Message::TabSelected(Tab::Backup));
        assert!(simulator(state.view()).find("Key share password").is_ok());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn network_has_a_single_new_room_action() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.active_tab = Tab::Connection;
        let mut ui = simulator(state.view());
        assert!(
            ui.find("New").is_err(),
            "the duplicate \"New\" button is back"
        );
        assert!(matches!(
            clicked(&state, "New room").as_slice(),
            [Message::NewRoom]
        ));
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn new_room_while_connected_offers_reconnect() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.active_tab = Tab::Connection;
        connected(&mut state);
        assert!(simulator(state.view()).find("Reconnect").is_err());
        let _ = state.update(Message::NewRoom);
        assert!(matches!(
            clicked(&state, "Reconnect").as_slice(),
            [Message::Connect]
        ));
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn create_needs_a_connection_and_a_password() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        assert!(
            simulator(state.view())
                .find("Connect to the network first.")
                .is_ok()
        );
        assert!(clicked(&state, "Create wallet").is_empty());

        connected(&mut state);
        assert!(clicked(&state, "Create wallet").is_empty());
        state.passwords.create = "short".to_string();
        state.passwords.create_confirm = "short".to_string();
        assert!(
            simulator(state.view())
                .find("The password must be at least 8 characters.")
                .is_ok()
        );
        assert!(clicked(&state, "Create wallet").is_empty());
        state.passwords.create = "password1".to_string();
        state.passwords.create_confirm = "password2".to_string();
        assert!(
            simulator(state.view())
                .find("The passwords don't match.")
                .is_ok()
        );
        assert!(clicked(&state, "Create wallet").is_empty());
        state.passwords.create_confirm = "password1".to_string();
        assert!(matches!(
            clicked(&state, "Create wallet").as_slice(),
            [Message::CreateWallet]
        ));

        // The new password isn't kept around once it's been handed over.
        let _ = state.update(Message::CreateWallet);
        assert!(state.passwords.create.is_empty() && state.passwords.create_confirm.is_empty());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn peer_signature_request_is_pinned_and_needs_the_password() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        connected(&mut state);
        with_wallet(&mut state);
        state.signing_request = Some(peer_request("9c1f4e2ab37d-ethereum-0", "00"));
        assert!(
            simulator(state.view())
                .find("Treasury · Ethereum · Account 0")
                .is_ok()
        );
        assert!(clicked(&state, "Approve & sign").is_empty());
        state.passwords.unlock = "pw".to_string();
        assert!(matches!(
            clicked(&state, "Approve & sign").as_slice(),
            [Message::ApproveSignatureRequest(id)] if id == "req-1"
        ));
        assert!(matches!(
            clicked(&state, "Reject").as_slice(),
            [Message::RejectSignatureRequest(id)] if id == "req-1"
        ));
        let _ = std::fs::remove_dir_all(keystore);
    }

    /// `r ‖ s ‖ v` (v = 27/28) by the single key `[7; 32]` over the EIP-191
    /// hash of `message`, plus that key's Ethereum address.
    fn eth_sign(message: &[u8]) -> (String, String) {
        let key = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let prehash = starlab_client::utils::eth_helper::eip191_hash(message);
        let (sig, recid) = key.sign_prehash_recoverable(&prehash);
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(27 + recid.to_byte());
        let pubkey = key.verifying_key().to_sec1_point(true);
        let address = starlab_core::accounts::address_for_chain(
            "ethereum",
            starlab_core::ecdsa::ECDSA_CURVE,
            pubkey.as_bytes(),
        )
        .unwrap();
        (format!("0x{}", hex::encode(bytes)), address)
    }

    #[test]
    fn ethereum_signature_is_split_into_r_s_v_and_verified_by_ecrecover() {
        let (sig, address) = eth_sign(b"Hello");
        let signed = SignedFor {
            chain: "ethereum",
            message_hex: "48656c6c6f".to_string(),
            prehashed: false,
            address: address.clone(),
            cosigned: false,
        };
        let summary = signature_summary(Some(&signed), &sig);
        assert!(
            summary.label.contains("ecrecover-compatible"),
            "{summary:?}"
        );
        assert_eq!(summary.parts.len(), 3);
        assert!(summary.parts[0].starts_with("r = 0x"));
        assert!(summary.parts[2] == "v = 27" || summary.parts[2] == "v = 28");
        assert!(summary.verified, "{summary:?}");
        assert!(summary.verification.contains(&address), "{summary:?}");
    }

    #[test]
    fn ethereum_signature_for_another_message_is_not_verified() {
        let (sig, address) = eth_sign(b"Hello");
        let signed = SignedFor {
            chain: "ethereum",
            message_hex: "00".to_string(),
            prehashed: false,
            address,
            cosigned: false,
        };
        let summary = signature_summary(Some(&signed), &sig);
        assert!(!summary.verified);
        assert!(
            summary.verification.starts_with("NOT verified"),
            "{summary:?}"
        );
    }

    /// A co-signer only has the request's EIP-191 digest; it verifies the
    /// signature against that digest and the request's account address.
    #[tokio::test]
    async fn cosigned_ethereum_signature_is_verified_against_the_request_digest() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        with_wallet(&mut state);
        let request = peer_request("9c1f4e2ab37d-ethereum-0", "00");
        let target = state.cosign_target(&request).expect("our wallet's account");
        assert!(target.cosigned && target.prehashed);
        assert_eq!(
            Some(target.address.clone()),
            state.signing_address().map(|(a, _)| a),
            "Ethereum account 0 of the ECDSA key"
        );
        // A signature over a digest by a known key, checked as prehashed.
        let (sig, address) = eth_sign(b"Hello");
        let digest = starlab_client::utils::eth_helper::eip191_hash(b"Hello");
        let signed = SignedFor {
            message_hex: hex::encode(digest),
            address,
            ..target
        };
        assert!(signature_summary(Some(&signed), &sig).verified);
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn ethereum_comes_from_the_ecdsa_key_bitcoin_from_taproot() {
        let wallet = WalletView {
            id: "w".to_string(),
            name: "w".to_string(),
            threshold: "2/3".to_string(),
            keys: vec![("secp256k1".to_string(), G.to_string())],
        };
        assert!(
            !wallet_has_chain(&wallet, "ethereum"),
            "no ECDSA key, no Ethereum"
        );
        assert!(wallet_has_chain(&wallet, "bitcoin"));
        let (address, path) = account_address(&wallet, "bitcoin", 0).unwrap();
        assert!(address.starts_with("bc1p"), "{address}");
        assert_eq!(path, "m/86'/0'/0'/0/0");
        assert_eq!(
            device_chains("secp256k1"),
            vec![("ethereum", "Ethereum"), ("bitcoin", "Bitcoin")]
        );
    }

    #[tokio::test]
    async fn non_hex_message_is_blocked_before_signing() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        connected(&mut state);
        with_wallet(&mut state);
        state.passwords.unlock = "pw".to_string();
        state.sign_hex = "hello".to_string();
        assert_eq!(state.sign_blocker(), Some("The message must be hex bytes."));
        state.sign_hex = "0x48656c6c6f".to_string();
        assert_eq!(state.sign_blocker(), None);
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn sign_tab_offers_ethereum_via_ecdsa_and_bitcoin() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        connected(&mut state);
        with_wallet(&mut state);
        state.active_tab = Tab::Sign;
        assert_eq!(
            state.sign_chain, "ethereum",
            "Ethereum is the default chain"
        );
        let mut ui = simulator(state.view());
        assert!(ui.find("Bitcoin").is_ok());
        assert!(
            ui.find("m/44'/60'/0'/0/0").is_err(),
            "path stays behind signing details"
        );
        drop(ui);
        state.show_signing_details = true;
        assert!(simulator(state.view()).find("m/44'/60'/0'/0/0").is_ok());
        assert_eq!(
            state.signing_wallet_id().as_deref(),
            Some("9c1f4e2ab37d-ethereum-0")
        );
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn ecdsa_setup_status_is_shown_and_a_waiting_setup_says_so() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.ecdsa_setup = EcdsaSetup::Preparing { elapsed_secs: 72 };
        state.active_tab = Tab::Connection;
        assert!(
            simulator(state.view())
                .find("Secure setup: preparing (1m 12s so far, usually 1-5 min)")
                .is_ok()
        );
        // FROST done, Ethereum key waiting for this device's primes.
        state.ceremony_open = true;
        state.ecdsa_keygen = true;
        state.ecdsa_phase = Some(DkgPhase::WaitingForPrimes);
        let mut ui = simulator(state.view());
        assert!(ui.find("Creating Ethereum wallet").is_ok());
        assert!(
            ui.find(
                "Preparing secure wallet setup (1m 12s so far, usually 1-5 min). Keep \
                 every device online."
            )
            .is_ok()
        );
        drop(ui);
        state.ecdsa_setup = EcdsaSetup::Ready;
        assert!(simulator(state.view()).find("Secure setup: ready").is_ok());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn running_ecdsa_ceremony_does_not_wait_for_next_wallet_primes() {
        let next_wallet = EcdsaSetup::Preparing { elapsed_secs: 72 };
        for phase in [DkgPhase::AuxInfo, DkgPhase::Keygen] {
            let detail = ecdsa_keygen_detail(Some(phase), next_wallet);
            assert!(detail.starts_with("Creating your shared Ethereum key"));
        }
        let detail = ecdsa_keygen_detail(Some(DkgPhase::WaitingForPrimes), next_wallet);
        assert!(detail.starts_with("Preparing secure wallet setup"));
    }

    #[tokio::test]
    async fn setup_has_one_action_per_section() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        connected(&mut state);
        state.passwords.join = "password1".to_string();
        state.passwords.join_confirm = "password1".to_string();
        // Section titles are headings, not a second set of buttons.
        assert!(clicked(&state, "Create a new wallet").is_empty());
        assert!(clicked(&state, "Join a wallet").is_empty());
        assert!(clicked(&state, "Join wallet").is_empty());
        state.invite_id = "7d2e0c4b".to_string();
        assert!(matches!(
            clicked(&state, "Join wallet").as_slice(),
            [Message::JoinWallet]
        ));
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn active_setup_focuses_devices_and_keeps_cancel_reachable() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.ceremony_open = true;
        state.active_session = Some(invite("active", "me", &["me", "laptop"]));
        let mut ui = simulator(state.view());
        assert!(ui.find("Current wallet setup").is_ok());
        assert!(ui.find("Create a new wallet").is_err());
        assert!(ui.find("Join a wallet").is_err());
        drop(ui);
        assert!(matches!(
            clicked(&state, "Cancel").as_slice(),
            [Message::CancelSetup]
        ));
        state.ceremony_open = false;
        assert!(simulator(state.view()).find("Create a new wallet").is_ok());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn export_needs_a_wallet_and_an_8_character_password() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.active_tab = Tab::Backup;
        state.passwords.backup = "password1".to_string();
        assert!(clicked(&state, "Export key share…").is_empty());
        with_wallet(&mut state);
        state.passwords.backup = "short".to_string();
        assert!(clicked(&state, "Export key share…").is_empty());
        state.passwords.backup = "password1".to_string();
        assert!(matches!(
            clicked(&state, "Export key share…").as_slice(),
            [Message::ExportShare]
        ));
        // Every key of the wallet is exported — the ECDSA file is the
        // Ethereum account.
        assert_eq!(
            state.export_target(),
            Some((
                "9c1f4e2ab37d".to_string(),
                vec!["secp256k1-ecdsa".to_string(), "secp256k1".to_string()]
            ))
        );
        let _ = std::fs::remove_dir_all(keystore);
    }

    fn key_press(
        key: iced::keyboard::Key,
        modifiers: iced::keyboard::Modifiers,
    ) -> iced::keyboard::Event {
        iced::keyboard::Event::KeyPressed {
            key: key.clone(),
            modified_key: key,
            physical_key: iced::keyboard::key::Physical::Unidentified(
                iced::keyboard::key::NativeCode::Unidentified,
            ),
            location: iced::keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        }
    }

    #[test]
    fn tab_moves_focus_forward_and_shift_tab_back() {
        use iced::keyboard::{Key, Modifiers, key::Named};
        let tab = Key::Named(Named::Tab);
        assert!(matches!(
            tab_focus(key_press(tab.clone(), Modifiers::empty())),
            Some(Message::FocusNext)
        ));
        assert!(matches!(
            tab_focus(key_press(tab, Modifiers::SHIFT)),
            Some(Message::FocusPrevious)
        ));
        assert!(tab_focus(key_press(Key::Named(Named::Enter), Modifiers::empty())).is_none());
    }

    /// The focus subscription only sees keys no widget captured: a focused
    /// text input must let Tab through.
    #[tokio::test]
    async fn focused_input_lets_tab_through() {
        let _renderer = renderer_lock();
        let (state, keystore) = test_state();
        let mut ui = simulator(state.view());
        ui.click("e.g. Treasury").expect("wallet name input");
        assert!(
            ui.find(iced_test::selector::is_focused()).is_ok(),
            "input not focused"
        );
        let status = ui.tap_key(iced::keyboard::Key::Named(iced::keyboard::key::Named::Tab));
        assert_eq!(status, iced::event::Status::Ignored);
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn empty_password_is_rejected() {
        assert!(password_problem("").is_some());
    }

    #[test]
    fn short_password_is_rejected() {
        assert!(password_problem("1234567").is_some());
    }

    #[test]
    fn eight_character_password_is_accepted() {
        assert_eq!(password_problem("12345678"), None);
    }

    #[test]
    fn new_password_must_match_its_confirmation() {
        assert!(new_password_problem("12345678", "12345679").is_some());
        assert_eq!(new_password_problem("12345678", "12345678"), None);
    }

    #[tokio::test]
    async fn signing_uses_the_selected_account_and_chain() {
        let (mut state, keystore) = test_state();
        with_wallet(&mut state);
        state.selected_account = 2;
        let _ = state.update(Message::SignChainSelected("bitcoin"));
        assert_eq!(
            state.signing_wallet_id().as_deref(),
            Some("9c1f4e2ab37d-bitcoin-2")
        );
        let _ = std::fs::remove_dir_all(keystore);
    }

    /// Render the main screens to PNGs for visual review:
    /// `SNAPSHOT_DIR=/some/dir cargo test snapshots`. Missing images are
    /// written; existing ones must match pixel for pixel.
    #[tokio::test]
    async fn snapshots() {
        let _renderer = renderer_lock();
        let Ok(dir) = std::env::var("SNAPSHOT_DIR") else {
            return;
        };
        let manifest = std::cell::RefCell::new(Vec::new());
        let shot = |state: &State, name: &str| {
            for (viewport, size) in [("normal", (1440.0, 900.0)), ("narrow", (1024.0, 768.0))] {
                let folder = std::path::Path::new(&dir).join(viewport);
                std::fs::create_dir_all(&folder).expect("snapshot folder");
                let mut ui =
                    iced_test::Simulator::with_size(iced::Settings::default(), size, state.view());
                let snapshot = ui.snapshot(&state.theme()).expect("snapshot");
                let path = folder.join(name);
                assert!(
                    snapshot.matches_image(&path).expect("png"),
                    "{viewport}/{name} changed"
                );
                manifest.borrow_mut().push(serde_json::json!({"state":name,"viewport":viewport,"width":size.0,"height":size.1,"provenance":"public fixture data; no private shares","file":format!("{viewport}/{name}-tiny-skia.png")}));
            }
        };

        let (mut state, keystore) = test_state();
        shot(&state, "1-offline");

        connected(&mut state);
        state.passwords = Passwords {
            create: "password1".to_string(),
            create_confirm: "password1".to_string(),
            join: "password1".to_string(),
            join_confirm: "password1".to_string(),
            unlock: "password1".to_string(),
            backup: String::new(),
        };
        state.wallet_name = "Treasury".to_string();
        shot(&state, "2-create");

        state.invites = vec![
            invite(
                "7d2e0c4b-1a9f-4c3e-b8d5-62f0a1e9c7b4",
                "laptop",
                &["laptop"],
            ),
            invite(
                "c0a5e8f1-3b6d-4e29-9f7a-18d4b2c6e053",
                "phone",
                &["phone", "tablet"],
            ),
        ];
        state.invite_id = "7d2e0c4b-1a9f-4c3e-b8d5-62f0a1e9c7b4".to_string();
        shot(&state, "3-join");

        state.invites.clear();
        state.ceremony_open = true;
        state.active_session = Some(invite(
            "5b8e2f71-0c4d-4a93-a6e1-9d3f7b20c85e",
            "me",
            &["me", "laptop"],
        ));
        shot(&state, "4-waiting");

        state.ceremony_open = false;
        state.active_session = None;
        with_wallet(&mut state);
        state.active_tab = Tab::Sign;
        state.sign_hex = "0x48656c6c6f".to_string();
        state.signing_request = Some(peer_request(
            "9c1f4e2ab37d-ethereum-0",
            "48656c6c6f2066726f6d20746865206c6170746f70",
        ));
        state.last_signature = "a3f1c9e2".repeat(16);
        shot(&state, "5-sign");
        state.signing_request = None;
        state.last_signature.clear();
        shot(&state, "06-wallet-sign");
        state.active_tab = Tab::Connection;
        shot(&state, "07-connection");
        state.server_url = "invalid server".to_string();
        shot(&state, "08-connection-invalid");
        state.server_url = "ws://127.0.0.1:9".to_string();
        state.active_tab = Tab::Backup;
        shot(&state, "09-backup-locked");
        state.passwords.backup = "fixture-password".to_string();
        shot(&state, "10-backup-ready");
        state.status = "Backup password is incorrect. Try again.".to_string();
        state.status_is_error = true;
        shot(&state, "11-backup-error");
        state.status = "Encrypted device backup saved.".to_string();
        state.status_is_error = false;
        shot(&state, "12-backup-success");
        state.active_tab = Tab::Setup;
        state.ceremony_open = true;
        state.ecdsa_keygen = true;
        state.ecdsa_setup = EcdsaSetup::Preparing { elapsed_secs: 72 };
        state.active_session = Some(invite(
            "fixture-active-setup",
            "me",
            &["me", "laptop", "phone"],
        ));
        for (name, phase) in [
            ("13-setup-primes", DkgPhase::WaitingForPrimes),
            ("14-setup-aux", DkgPhase::AuxInfo),
            ("15-setup-keygen", DkgPhase::Keygen),
        ] {
            state.ecdsa_phase = Some(phase);
            shot(&state, name);
        }
        state.ceremony_open = false;
        state.ecdsa_keygen = false;
        state.ecdsa_phase = None;
        state.active_session = None;
        let previous_status = state.status.clone();
        let previous_status_is_error = state.status_is_error;
        state.status =
            "Wallet setup failed: a device disconnected. Reconnect the devices and try again."
                .to_string();
        state.status_is_error = true;
        shot(&state, "15b-setup-failed");
        state.status = previous_status;
        state.status_is_error = previous_status_is_error;
        state.active_tab = Tab::Sign;
        state.selected_account = 1;
        let mut second_wallet = state.wallets[0].clone();
        second_wallet.name = "Operations".to_string();
        second_wallet.id = "fixture-operations".to_string();
        state.wallets.push(second_wallet);
        shot(&state, "16-wallets-accounts");
        state.sign_hex = "invalid hex".to_string();
        shot(&state, "17-sign-invalid");
        state.sign_hex = "48656c6c6f".to_string();
        state.signing_request = Some(peer_request(
            "9c1f4e2ab37d-ethereum-0",
            "fa4de0de7cb829ad54bf4982c3603afe1596fd39a76004184fa2844fda56ac6c",
        ));
        state.passwords.unlock.clear();
        shot(&state, "18-approval-password");
        state.passwords.unlock = "fixture-password".to_string();
        state.pending_action = Some(PendingAction::CoSign);
        state.signing_state = SigningState::Aggregating;
        shot(&state, "19-approval-working");
        state.pending_action = None;
        state.signing_state =
            SigningState::Failed("The other device declined this request.".to_string());
        shot(&state, "20-approval-declined");
        state.signing_state =
            SigningState::Failed("Wallet password is incorrect. Try again.".to_string());
        shot(&state, "20b-approval-password-error");
        state.signing_request = None;
        state.signing_state = SigningState::Complete;
        state.selected_account = 0;
        state.wallets[0].keys[0].1 =
            "032affa8a1c464656c918705206638118d36adc42fb4310f9b12f6b027a0a53b8b".to_string();
        state.last_signature = "7937057016c1e21b9ff07affded820bf5aa5bf483d9610a27584716007925fd90b4fe3b114f15ca8dc3332f44250e5904611bd4cab4a53334aa17bbd9cd0a8cc1c".to_string();
        state.last_signed = Some(SignedFor {
            chain: "ethereum",
            message_hex: "fa4de0de7cb829ad54bf4982c3603afe1596fd39a76004184fa2844fda56ac6c"
                .to_string(),
            prehashed: true,
            address: "0x2fb6ae33558e46ec6baa39c9c98cd00f4b0f7548".to_string(),
            cosigned: true,
        });
        shot(&state, "21-signature-verified");
        state.sign_chain = "bitcoin";
        state.last_signature.clear();
        shot(&state, "21b-bitcoin-sign");
        state.active_tab = Tab::Activity;
        shot(&state, "22-activity-empty");
        state.log_messages = vec![
            "14:50:00 [INFO] Wallet setup started with 3 devices.".to_string(),
            "14:52:00 [INFO] Ethereum wallet is ready.".to_string(),
            "14:53:00 [ERROR] Another device declined the signature request.".to_string(),
            "14:55:00 [INFO] Signature verified for Treasury, account 0.".to_string(),
        ];
        shot(&state, "23-activity-events");
        state.show_activity_details = true;
        shot(&state, "24-activity-details");
        state.active_tab = Tab::Sign;
        state.signing_curve = "ed25519";
        state.wallets.truncate(1);
        state.wallets[0].keys = vec![(
            "ed25519".to_string(),
            "5866666666666666666666666666666666666666666666666666666666666666".to_string(),
        )];
        state.ecdsa_setup = EcdsaSetup::NotNeeded;
        state.sign_chain = "solana";
        shot(&state, "25-solana-sign");
        state.sign_chain = "sui";
        shot(&state, "26-sui-sign");
        std::fs::write(
            std::path::Path::new(&dir).join("manifest.json"),
            serde_json::to_string_pretty(&manifest.into_inner()).unwrap(),
        )
        .expect("snapshot manifest");

        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn extracts_room_from_query() {
        assert_eq!(
            split_signal_room("wss://sig.example/ws?room=abc"),
            ("wss://sig.example/ws".into(), Some("abc".into()))
        );
    }

    #[test]
    fn ignores_room_suffix_in_other_keys() {
        assert_eq!(
            split_signal_room("wss://sig.example/ws?chatroom=x"),
            ("wss://sig.example/ws?chatroom=x".into(), None)
        );
    }

    #[test]
    fn finds_room_after_lookalike_key() {
        assert_eq!(
            split_signal_room("wss://sig.example/ws?chatroom=x&room=abc"),
            ("wss://sig.example/ws?chatroom=x".into(), Some("abc".into()))
        );
    }

    #[test]
    fn strips_middle_room_param_cleanly() {
        assert_eq!(
            split_signal_room("wss://sig.example/ws?a=1&room=abc&b=2"),
            ("wss://sig.example/ws?a=1&b=2".into(), Some("abc".into()))
        );
    }

    #[test]
    fn empty_room_value_is_none() {
        assert_eq!(
            split_signal_room("wss://sig.example/ws?room="),
            ("wss://sig.example/ws".into(), None)
        );
    }

    #[test]
    fn url_without_query_is_unchanged() {
        assert_eq!(
            split_signal_room("  wss://sig.example/ws  "),
            ("wss://sig.example/ws".into(), None)
        );
    }
}
