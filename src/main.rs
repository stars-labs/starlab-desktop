//! Starlab Desktop — an Iced GUI over the starlab-mpc engine.
//!
//! Elm architecture: [`State`] is the model, [`Message`]s are handled in
//! [`State::update`], and `view` renders the model. The async core pushes
//! state as [`UiEvent`]s over an mpsc channel that a [`Subscription`] turns
//! into [`Message::Ui`].
//!
//! Layout: the left column holds what the other screens depend on — the
//! network (server + room) and the wallets (plus the wallet password). The
//! main area follows the user's flow: set up a wallet, sign with it, and an
//! activity log. Anything that needs attention right now (a running wallet
//! setup, a peer's signature request) is pinned above the tabs.

mod core_adapter;
mod ui_callback;

use std::sync::{Arc, Mutex as StdMutex};

use iced::futures::stream;
use iced::widget::{
    Column, Row, Space, button, column, container, progress_bar, row, scrollable, text, text_input,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};

use core_adapter::{CoreAdapter, DEFAULT_THRESHOLD, DEFAULT_TOTAL};
use starlab_client::core::{SigningRequest, SigningState};
use ui_callback::{Invite, UiEvent, WalletView};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    iced::application(State::new, State::update, State::view)
        .title("Starlab Desktop")
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMode {
    Create,
    Join,
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
    PasswordChanged(String),
    ImportShare,
    ExportShare,

    // Wallet setup
    SetupModeSelected(SetupMode),
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
            keystore_path: format!(
                "{}/.frost_keystore",
                std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
            ),
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
    /// Encrypts this device's key shares; needed to create, join and sign.
    password: String,

    // Sessions and the wallet-setup ceremony
    invites: Vec<Invite>,
    active_session: Option<Invite>,
    ceremony_open: bool,
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

    // UI
    active_tab: Tab,
    setup_mode: SetupMode,
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
            password: String::new(),
            invites: Vec::new(),
            active_session: None,
            ceremony_open: false,
            dkg_active: false,
            dkg_round: 0,
            dkg_progress: 0.0,
            signing_request: None,
            sign_chain: starlab_core::accounts::chains_for_curve(signing_curve)[0].0,
            sign_hex: String::new(),
            signing_state: SigningState::Idle,
            last_signature: String::new(),
            active_tab: Tab::Setup,
            setup_mode: SetupMode::Create,
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
        Theme::Dark
    }

    fn subscription(&self) -> Subscription<Message> {
        // `Subscription::run` identifies the subscription by the worker fn,
        // so it's spawned exactly once for the app's life.
        Subscription::run(ui_bridge)
    }

    // -- Update ---------------------------------------------------------

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Ui(event) => {
                self.apply_ui_event(event);
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
            Message::PasswordChanged(v) => {
                self.password = v;
                Task::none()
            }
            Message::ImportShare => {
                if self.import_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let password = self.password.clone();
                self.pending_action = Some(PendingAction::ImportShare);
                self.set_status("Importing a key share");
                action(async move { adapter.import_share(password).await })
            }
            Message::ExportShare => {
                let Some((wallet_id, curve)) = self.export_target() else {
                    return Task::none();
                };
                if self.export_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let password = self.password.clone();
                self.pending_action = Some(PendingAction::ExportShare);
                self.set_status("Exporting the key share");
                action(async move { adapter.export_share(wallet_id, curve, password).await })
            }

            Message::SetupModeSelected(mode) => {
                self.setup_mode = mode;
                Task::none()
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
                if self.setup_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let (name, password) = (self.wallet_name.clone(), self.password.clone());
                self.pending_action = Some(PendingAction::CreateWallet);
                self.set_status("Creating the wallet invite");
                action(async move { adapter.create_wallet(name, password).await })
            }
            Message::JoinWallet => {
                if self.setup_blocker().is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let (id, password) = (self.invite_id.trim().to_string(), self.password.clone());
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
                let (hex, password) = (self.sign_hex.trim().to_string(), self.password.clone());
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
                let adapter = self.adapter.clone();
                let password = self.password.clone();
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
            UiEvent::SigningRequest(request) => self.signing_request = request,
            UiEvent::SigningState(state) => self.signing_state = state,
            UiEvent::SigningComplete(signature) => {
                // A co-signer's copy of the signature belongs to the requester.
                if self.pending_action == Some(PendingAction::CoSign) {
                    self.set_status("Co-signed — the requesting device has the signature");
                } else {
                    self.last_signature = signature;
                    self.set_status("Signature ready");
                }
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

    /// Why Create/Join is disabled, if it is.
    fn setup_blocker(&self) -> Option<&'static str> {
        if !self.connected {
            Some("Connect to the network first.")
        } else if let Some(problem) = password_problem(&self.password) {
            Some(problem)
        } else if self.wallet_busy() {
            Some("A wallet setup is already in progress.")
        } else if self.setup_mode == SetupMode::Join && self.invite_id.trim().is_empty() {
            Some("Pick an invite or paste its ID.")
        } else {
            None
        }
    }

    /// Why "Import key share…" is disabled, if it is.
    fn import_blocker(&self) -> Option<&'static str> {
        if self.pending_action.is_some() {
            Some("Another action is in progress.")
        } else if self.password.is_empty() {
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
            password_problem(&self.password)
        }
    }

    /// `(wallet id, curve)` of the share "Export key share…" writes: the
    /// selected wallet's key on this device's curve, else its first key.
    fn export_target(&self) -> Option<(String, String)> {
        let wallet = self.active_wallet()?;
        let (curve, _) = wallet
            .keys
            .iter()
            .find(|(curve, _)| curve == self.signing_curve)
            .or_else(|| wallet.keys.first())?;
        Some((wallet.id.clone(), curve.clone()))
    }

    /// Why "Request signature" is disabled, if it is.
    fn sign_blocker(&self) -> Option<&'static str> {
        if self.signing_wallet_id().is_none() {
            Some("This wallet has no key for this device's curve.")
        } else if !self.connected {
            Some("Connect to the network first.")
        } else if self.password.is_empty() {
            Some("Enter your wallet password first (left panel).")
        } else if self.sign_hex.trim().is_empty() {
            Some("Enter the message to sign.")
        } else {
            None
        }
    }

    /// Why a peer's signature request can't be approved yet, if it can't.
    fn approve_blocker(&self) -> Option<&'static str> {
        if !self.connected {
            Some("Connect to the network first.")
        } else if self.password.is_empty() {
            Some("Enter your wallet password to approve.")
        } else if self.pending_action.is_some() {
            Some("Another action is in progress.")
        } else {
            None
        }
    }

    fn active_wallet(&self) -> Option<&WalletView> {
        self.wallets.get(self.active_wallet_index)
    }

    /// The account wallet signing uses: `<root>-<chain>-<account>`.
    fn signing_wallet_id(&self) -> Option<String> {
        let wallet = self.active_wallet()?;
        wallet
            .keys
            .iter()
            .any(|(curve, _)| curve == self.signing_curve)
            .then(|| {
                format!(
                    "{}-{}-{}",
                    wallet.id, self.sign_chain, self.selected_account
                )
            })
    }

    /// `(address, derivation path)` of the signing account on the chosen chain.
    fn signing_address(&self) -> Option<(String, String)> {
        let wallet = self.active_wallet()?;
        let (_, group_key) = wallet.keys.iter().find(|(c, _)| c == self.signing_curve)?;
        let group_key = hex::decode(group_key).ok()?;
        let addresses = starlab_core::accounts::account_addresses(
            self.signing_curve,
            &group_key,
            self.selected_account,
        )
        .ok()?;
        let index = starlab_core::accounts::chains_for_curve(self.signing_curve)
            .iter()
            .position(|(key, _)| *key == self.sign_chain)?;
        let (_, path, address) = addresses.into_iter().nth(index)?;
        Some((address, path))
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
        let chain = starlab_core::accounts::chains_for_curve(self.signing_curve)
            .iter()
            .find(|(key, _)| *key == chain)
            .map_or(chain, |(_, label)| *label);
        format!("{name} · {chain} · Account {account}")
    }

    // -- View -----------------------------------------------------------

    fn view(&self) -> Element<'_, Message> {
        container(
            column![
                self.header(),
                row![
                    container(self.sidebar()).width(Length::Fixed(340.0)),
                    container(self.main_panel()).width(Length::Fill),
                ]
                .spacing(18)
                .height(Length::Fill),
                self.status_bar(),
            ]
            .spacing(14),
        )
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn header(&self) -> Element<'_, Message> {
        let (dot, label, color) = if self.connected {
            let label = match self.peers {
                0 => "Connected".to_string(),
                1 => "Connected · 1 peer".to_string(),
                n => format!("Connected · {n} peers"),
            };
            ("●", label, accent())
        } else if self.connected_url.is_some() {
            ("◌", "Connecting…".to_string(), warning())
        } else {
            ("○", "Offline".to_string(), muted())
        };
        row![
            column![
                text("Starlab Desktop").size(22),
                text("MPC Wallet").size(12).color(muted()),
            ]
            .spacing(2),
            Space::new().width(Length::Fill),
            column![
                row![text(dot).color(color), text(label).size(13).color(color)]
                    .spacing(6)
                    .align_y(Alignment::Center),
                text(format!("Device {}", self.device_id))
                    .size(12)
                    .color(muted()),
            ]
            .spacing(2)
            .align_x(Alignment::End),
        ]
        .align_y(Alignment::Center)
        .into()
    }

    fn status_bar(&self) -> Element<'_, Message> {
        text(&self.status)
            .size(12)
            .color(if self.status_is_error {
                danger()
            } else {
                muted()
            })
            .into()
    }

    // ---- Sidebar ----

    fn sidebar(&self) -> Element<'_, Message> {
        scrollable(column![self.network_card(), self.wallets_card()].spacing(12)).into()
    }

    fn network_card(&self) -> Element<'_, Message> {
        let mut body = column![
            field(
                "Signal server",
                text_input("wss://panda.qzz.io", &self.server_url)
                    .on_input(Message::ServerUrlChanged),
            ),
            field(
                "Room ID",
                text_input("Room ID", &self.room).on_input(Message::RoomChanged),
            ),
            row![
                action_button("New room").on_press(Message::NewRoom),
                action_button("Copy").on_press(Message::CopyRoom),
            ]
            .spacing(8),
            hint("Devices find each other through the same server and room ID."),
        ]
        .spacing(10);

        if self.network_changed() {
            let label = if self.connected {
                "Reconnect"
            } else {
                "Connect"
            };
            body = body.push(
                action_button(label)
                    .style(button::primary)
                    .width(Length::Fill)
                    .on_press_maybe(self.can_connect().then_some(Message::Connect)),
            );
            if self.connected {
                body = body.push(hint(if self.can_connect() {
                    "Reconnect to use the new server or room."
                } else {
                    "Finish or cancel the wallet setup before switching rooms."
                }));
            }
        }

        card("Network", body.into())
    }

    fn wallets_card(&self) -> Element<'_, Message> {
        let mut body = Column::new().spacing(10);
        if self.wallets.is_empty() {
            body = body.push(hint(
                "No wallets on this device yet. Create or join one under Set up wallet.",
            ));
        } else {
            for (i, w) in self.wallets.iter().enumerate() {
                let mut entry = Column::new().spacing(3).push(
                    button(text(format!("{} · {}", w.name, w.threshold)).size(13))
                        .width(Length::Fill)
                        .style(if i == self.active_wallet_index {
                            button::primary
                        } else {
                            button::secondary
                        })
                        .on_press(Message::WalletSelected(i)),
                );
                // One line per chain address of the selected account, derived
                // from the group key via the engine's account model.
                for (curve, group_key) in &w.keys {
                    let Ok(group_key) = hex::decode(group_key) else {
                        continue;
                    };
                    let Ok(addresses) = starlab_core::accounts::account_addresses(
                        curve,
                        &group_key,
                        self.selected_account,
                    ) else {
                        continue;
                    };
                    for (chain, _path, address) in addresses {
                        entry = entry.push(
                            text(format!("{chain}  {}", short_addr(&address)))
                                .size(12)
                                .color(muted()),
                        );
                    }
                }
                body = body.push(entry);
            }
            // BIP-44 account picker: [Account 0] [Account 1] … [+]. Switching
            // is a pure State change — addresses below re-derive in this view.
            let mut accounts = Row::new().spacing(6);
            for i in 0..=self.max_account {
                accounts = accounts.push(segment_button(
                    format!("Account {i}"),
                    Message::SelectAccount(i),
                    i == self.selected_account,
                ));
            }
            accounts = accounts.push(button(text("+").size(13)).on_press(Message::AddAccount));
            body = body.push(field(
                "Account",
                scrollable(accounts).direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::default(),
                )),
            ));
        }

        body = body.push(section_divider()).push(field(
            "Wallet password",
            text_input("Password", &self.password)
                .secure(true)
                .on_input(Message::PasswordChanged),
        ));
        body = body.push(hint(
            "Encrypts this device's key shares (at least 8 characters). Needed to create, \
             join and sign.",
        ));
        let backup = if self.wallets.is_empty() {
            self.import_blocker()
        } else {
            self.export_blocker().or(self.import_blocker())
        };
        body = body.push(section_divider()).push(
            row![
                action_button("Import key share…").on_press_maybe(
                    self.import_blocker()
                        .is_none()
                        .then_some(Message::ImportShare)
                ),
                action_button("Export key share…").on_press_maybe(
                    self.export_blocker()
                        .is_none()
                        .then_some(Message::ExportShare)
                ),
            ]
            .spacing(8),
        );
        body = body.push(match backup {
            Some(reason) => text(reason).size(12).color(warning()).into(),
            None => hint(
                "Export saves this device's encrypted key share of the selected wallet; \
                 import restores one.",
            ),
        });

        card("Wallets", body.into())
    }

    // ---- Main area ----

    fn main_panel(&self) -> Element<'_, Message> {
        let mut content = Column::new().spacing(14);
        if let Some(banner) = self.setup_banner() {
            content = content.push(banner);
        }
        if let Some(requests) = self.signature_requests() {
            content = content.push(requests);
        }
        content = content.push(
            row![
                tab_button("Set up wallet", Tab::Setup, self.active_tab),
                tab_button("Sign", Tab::Sign, self.active_tab),
                tab_button("Activity", Tab::Activity, self.active_tab),
            ]
            .spacing(6),
        );
        content = content.push(match self.active_tab {
            Tab::Setup => self.setup_tab(),
            Tab::Sign => self.sign_tab(),
            Tab::Activity => self.activity_tab(),
        });
        scrollable(content).into()
    }

    /// Pinned while a wallet setup is running: who joined, the invite to
    /// share, DKG progress, and the way out.
    fn setup_banner(&self) -> Option<Element<'_, Message>> {
        if !(self.ceremony_open || self.dkg_active) {
            return None;
        }
        let own = self.own_invite();
        let joined = self.active_session.as_ref().map(|s| {
            format!(
                "{} of {} devices have joined.",
                s.participants.len(),
                s.total
            )
        });
        let (title, detail) = if self.dkg_active {
            (
                "Generating keys",
                format!(
                    "Round {} of 2 — keep every device online until it finishes.",
                    self.dkg_round.max(1)
                ),
            )
        } else if own.is_some() {
            (
                "Waiting for devices to join",
                format!(
                    "{} Share the invite ID with the other devices.",
                    joined.unwrap_or_default()
                ),
            )
        } else {
            (
                "Joined — waiting for the other devices",
                joined.unwrap_or_default(),
            )
        };

        let mut body = column![
            row![
                text(title).size(15),
                Space::new().width(Length::Fill),
                action_button("Cancel")
                    .style(button::danger)
                    .on_press(Message::CancelSetup),
            ]
            .align_y(Alignment::Center),
            text(detail).size(13).color(muted()),
        ]
        .spacing(8);
        if let Some(invite) = own.filter(|_| !self.dkg_active) {
            body = body.push(
                row![
                    text("Invite ID").size(12).color(muted()),
                    text(&invite.id).size(13),
                    Space::new().width(Length::Fill),
                    action_button("Copy invite").on_press(Message::CopyInvite),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
        }
        if self.dkg_active {
            body = body.push(progress_bar(0.0..=1.0, self.dkg_progress));
        }
        Some(
            container(body)
                .padding(14)
                .width(Length::Fill)
                .style(highlight_style)
                .into(),
        )
    }

    /// Pinned while a peer asks this device to co-sign.
    fn signature_requests(&self) -> Option<Element<'_, Message>> {
        let request = self
            .signing_request
            .as_ref()
            .filter(|r| r.session_id.is_some())?;
        let blocker = self.approve_blocker();
        let actions: Element<'_, Message> = match &self.signing_state {
            SigningState::Commitment | SigningState::Share | SigningState::Aggregating => {
                text("Co-signing…").size(13).color(accent()).into()
            }
            SigningState::Failed(error) => row![
                text(format!("Signing failed: {error}"))
                    .size(12)
                    .color(danger()),
                Space::new().width(Length::Fill),
                action_button("Dismiss").on_press(Message::DismissSigning),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
            _ => row![
                text(blocker.unwrap_or_default()).size(12).color(warning()),
                Space::new().width(Length::Fill),
                action_button("Reject")
                    .style(button::secondary)
                    .on_press(Message::RejectSignatureRequest(request.id.clone())),
                action_button("Approve & sign")
                    .style(button::primary)
                    .on_press_maybe(
                        blocker
                            .is_none()
                            .then(|| Message::ApproveSignatureRequest(request.id.clone())),
                    ),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        };
        let mut body = column![
            text("Signature request").size(15),
            text("Another device of this wallet asks this device to co-sign.").size(13),
            text(self.describe_account_wallet(&request.wallet_id))
                .size(12)
                .color(muted()),
        ]
        .spacing(4);
        if let Some(label) = &request.display_label {
            body = body.push(text(label).size(12).color(faint()));
        }
        body = body
            .push(
                text(format!("Message  {}", short_addr(&request.message_hex)))
                    .size(12)
                    .color(faint()),
            )
            .push(actions);
        Some(
            container(body)
                .padding(14)
                .width(Length::Fill)
                .style(highlight_style)
                .into(),
        )
    }

    fn setup_tab(&self) -> Element<'_, Message> {
        let modes = row![
            segment_button(
                "Create a new wallet",
                Message::SetupModeSelected(SetupMode::Create),
                self.setup_mode == SetupMode::Create,
            ),
            segment_button(
                "Join with an invite",
                Message::SetupModeSelected(SetupMode::Join),
                self.setup_mode == SetupMode::Join,
            ),
        ]
        .spacing(8);
        let blocker = self.setup_blocker();

        let body: Element<'_, Message> = match self.setup_mode {
            SetupMode::Create => column![
                text(format!(
                    "Start a {DEFAULT_THRESHOLD}-of-{DEFAULT_TOTAL} wallet on this device, then share \
                     its invite ID with {} other devices. Any {DEFAULT_THRESHOLD} of the \
                     {DEFAULT_TOTAL} can sign.",
                    DEFAULT_TOTAL - 1
                ))
                .size(13)
                .color(muted()),
                field(
                    "Wallet name",
                    text_input("e.g. Treasury", &self.wallet_name)
                        .on_input(Message::WalletNameChanged),
                ),
                action_row(
                    action_button("Create wallet")
                        .style(button::primary)
                        .on_press_maybe(blocker.is_none().then_some(Message::CreateWallet)),
                    blocker,
                ),
            ]
            .spacing(12)
            .into(),
            SetupMode::Join => {
                let mut invites = Column::new().spacing(6);
                let wallet_invites = wallet_invites(&self.device_id, &self.invites);
                if wallet_invites.is_empty() {
                    invites = invites.push(hint("No invites in this room yet."));
                }
                for invite in wallet_invites {
                    invites = invites.push(
                        button(
                            column![
                                text(&invite.id).size(13),
                                text(format!(
                                    "from {} · {} of {} joined",
                                    invite.proposer,
                                    invite.participants.len(),
                                    invite.total
                                ))
                                .size(11),
                            ]
                            .spacing(2),
                        )
                        .width(Length::Fill)
                        .style(if invite.id == self.invite_id.trim() {
                            button::primary
                        } else {
                            button::secondary
                        })
                        .on_press(Message::InviteIdChanged(invite.id.clone())),
                    );
                }
                column![
                    text("Join a wallet another device started: pick its invite, or paste the invite ID.")
                        .size(13)
                        .color(muted()),
                    field("Invites in this room", invites),
                    field(
                        "Invite ID",
                        text_input("Paste invite ID", &self.invite_id)
                            .on_input(Message::InviteIdChanged),
                    ),
                    action_row(
                        action_button("Join wallet")
                            .style(button::primary)
                            .on_press_maybe(blocker.is_none().then_some(Message::JoinWallet)),
                        blocker,
                    ),
                ]
                .spacing(12)
                .into()
            }
        };

        card(
            "Set up a shared wallet",
            column![modes, body].spacing(16).into(),
        )
    }

    fn sign_tab(&self) -> Element<'_, Message> {
        let Some(wallet) = self.active_wallet() else {
            return card(
                "Sign a message",
                column![
                    hint("You need a shared wallet before you can sign."),
                    action_button("Set up a wallet").on_press(Message::TabSelected(Tab::Setup)),
                ]
                .spacing(12)
                .into(),
            );
        };

        let mut chains = Row::new().spacing(8);
        for (key, label) in starlab_core::accounts::chains_for_curve(self.signing_curve) {
            chains = chains.push(segment_button(
                *label,
                Message::SignChainSelected(key),
                *key == self.sign_chain,
            ));
        }
        let address: Element<'_, Message> = match self.signing_address() {
            Some((address, path)) => {
                row![text(address).size(13), text(path).size(11).color(muted()),]
                    .spacing(10)
                    .align_y(Alignment::Center)
                    .into()
            }
            None => hint("This wallet has no key for this device's curve."),
        };
        let message_hint = match self.sign_chain {
            "ethereum" => "Hex bytes; signed as an EIP-191 personal message.",
            "bitcoin" => "The 32-byte BIP-341 sighash, in hex.",
            _ => "Hex bytes to sign.",
        };

        let signing = self.pending_action == Some(PendingAction::Sign);
        let blocker = if signing { None } else { self.sign_blocker() };
        let mut body = column![
            column![
                text(format!(
                    "{} · Account {}",
                    wallet.name, self.selected_account
                ))
                .size(15),
                hint("Choose the wallet and account in the left panel."),
            ]
            .spacing(4),
            field("Chain", chains),
            field("Signing address", address),
            field(
                "Message",
                text_input("0x…", &self.sign_hex).on_input(Message::SignHexChanged),
            ),
            hint(message_hint),
            action_row(
                action_button(if signing {
                    "Signing…"
                } else {
                    "Request signature"
                })
                .style(button::primary)
                .on_press_maybe((blocker.is_none() && !signing).then_some(Message::Sign),),
                blocker,
            ),
        ]
        .spacing(12);

        if signing {
            body = body.push(
                text(signing_phase(&self.signing_state))
                    .size(13)
                    .color(accent()),
            );
        } else if let SigningState::Failed(error) = &self.signing_state {
            body = body.push(
                text(format!("Signing failed: {error}"))
                    .size(13)
                    .color(danger()),
            );
        }
        if !self.last_signature.is_empty() {
            body = body.push(field(
                "Signature",
                row![
                    text(&self.last_signature).size(12).width(Length::Fill),
                    action_button("Copy").on_press(Message::CopySignature),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            ));
        }

        card("Sign a message", body.into())
    }

    fn activity_tab(&self) -> Element<'_, Message> {
        let mut lines = Column::new().spacing(2);
        if self.log_messages.is_empty() {
            lines = lines.push(hint("Nothing yet."));
        }
        for line in &self.log_messages {
            lines = lines.push(text(line).size(12).color(faint()));
        }
        card(
            "Activity",
            scrollable(lines).height(Length::Fixed(420.0)).into(),
        )
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
        Some("Set a wallet password first (left panel).")
    } else if password.chars().count() < MIN_PASSWORD_LEN {
        Some("The wallet password must be at least 8 characters.")
    } else {
        None
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

fn card<'a>(title: &'a str, body: Element<'a, Message>) -> Element<'a, Message> {
    container(column![text(title).size(15), body].spacing(12))
        .padding(14)
        .width(Length::Fill)
        .style(panel_style)
        .into()
}

/// A labelled form field.
fn field<'a>(label: &'a str, input: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![text(label).size(12).color(muted()), input.into()]
        .spacing(4)
        .into()
}

fn hint(message: &str) -> Element<'_, Message> {
    text(message).size(12).color(muted()).into()
}

/// A right-aligned primary action with the reason it's disabled on the left.
fn action_row<'a>(
    action: iced::widget::Button<'a, Message>,
    blocker: Option<&'a str>,
) -> Element<'a, Message> {
    row![
        text(blocker.unwrap_or_default()).size(12).color(warning()),
        Space::new().width(Length::Fill),
        action,
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .into()
}

/// A command button (Connect, Create wallet, Copy, …).
fn action_button(label: &str) -> iced::widget::Button<'_, Message> {
    button(text(label).size(14)).padding([7, 14])
}

/// One option of a segmented choice (tabs, modes, chains, accounts).
fn segment_button<'a>(
    label: impl text::IntoFragment<'a>,
    message: Message,
    selected: bool,
) -> iced::widget::Button<'a, Message> {
    button(text(label).size(13))
        .style(if selected {
            button::primary
        } else {
            button::secondary
        })
        .on_press(message)
}

fn tab_button(label: &str, tab: Tab, active: Tab) -> iced::widget::Button<'_, Message> {
    segment_button(label, Message::TabSelected(tab), tab == active)
}

fn section_divider<'a>() -> Element<'a, Message> {
    container(Space::new().height(1))
        .height(1)
        .width(Length::Fill)
        .style(|_theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(72, 78, 88))),
            ..container::Style::default()
        })
        .into()
}

fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb8(45, 49, 56))),
        text_color: Some(Color::from_rgb8(226, 230, 236)),
        border: Border {
            width: 1.0,
            radius: 6.0.into(),
            color: Color::from_rgb8(65, 72, 82),
        },
        ..container::Style::default()
    }
}

/// A panel that needs attention now (running setup, incoming requests).
fn highlight_style(theme: &Theme) -> container::Style {
    container::Style {
        border: Border {
            width: 1.0,
            radius: 6.0.into(),
            color: accent(),
        },
        ..panel_style(theme)
    }
}

fn short_addr(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}…{}", &addr[..10], &addr[addr.len() - 6..])
    } else {
        addr.to_string()
    }
}

fn accent() -> Color {
    Color::from_rgb(0.063, 0.725, 0.506) // #10B981
}

fn warning() -> Color {
    Color::from_rgb8(236, 190, 104)
}

fn danger() -> Color {
    Color::from_rgb8(248, 113, 113)
}

fn muted() -> Color {
    Color::from_rgb(0.58, 0.64, 0.72) // #94A3B8
}

fn faint() -> Color {
    Color::from_rgb(0.80, 0.84, 0.88) // #CBD5E1
}

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

    /// A 2-of-3 wallet whose group key is the secp256k1 generator — any valid
    /// point works for address derivation.
    fn with_wallet(state: &mut State) {
        state.wallets = vec![WalletView {
            id: "9c1f4e2ab37d".to_string(),
            name: "Treasury".to_string(),
            threshold: "2/3".to_string(),
            keys: vec![(
                "secp256k1".to_string(),
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            )],
        }];
    }

    fn clicked(state: &State, label: &str) -> Vec<Message> {
        let mut ui = simulator(state.view());
        ui.click(label).unwrap_or_else(|e| panic!("{label}: {e}"));
        ui.into_messages().collect()
    }

    #[tokio::test]
    async fn network_has_a_single_new_room_action() {
        let _renderer = renderer_lock();
        let (state, keystore) = test_state();
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
        state.password = "short".to_string();
        assert!(
            simulator(state.view())
                .find("The wallet password must be at least 8 characters.")
                .is_ok()
        );
        assert!(clicked(&state, "Create wallet").is_empty());
        state.password = "password1".to_string();
        assert!(matches!(
            clicked(&state, "Create wallet").as_slice(),
            [Message::CreateWallet]
        ));
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
        state.password = "pw".to_string();
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

    #[tokio::test]
    async fn export_needs_a_wallet_and_an_8_character_password() {
        let _renderer = renderer_lock();
        let (mut state, keystore) = test_state();
        state.password = "password1".to_string();
        assert!(clicked(&state, "Export key share…").is_empty());
        with_wallet(&mut state);
        state.password = "short".to_string();
        assert!(clicked(&state, "Export key share…").is_empty());
        state.password = "password1".to_string();
        assert!(matches!(
            clicked(&state, "Export key share…").as_slice(),
            [Message::ExportShare]
        ));
        assert_eq!(
            state.export_target(),
            Some(("9c1f4e2ab37d".to_string(), "secp256k1".to_string()))
        );
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
        let shot = |state: &State, name: &str| {
            let mut ui = iced_test::Simulator::with_size(
                iced::Settings::default(),
                (1440.0, 900.0),
                state.view(),
            );
            let snapshot = ui.snapshot(&Theme::Dark).expect("snapshot");
            let path = std::path::Path::new(&dir).join(name);
            assert!(
                snapshot.matches_image(&path).expect("png"),
                "{name} changed"
            );
        };

        let (mut state, keystore) = test_state();
        shot(&state, "1-offline");

        connected(&mut state);
        state.password = "password1".to_string();
        state.wallet_name = "Treasury".to_string();
        shot(&state, "2-create");

        state.setup_mode = SetupMode::Join;
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

        state.setup_mode = SetupMode::Create;
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
