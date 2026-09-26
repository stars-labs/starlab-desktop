//! Native MPC Wallet node — Iced GUI.
//!
//! Ported from Slint to Iced (MIT-licensed) so the GUI stack is
//! compatible with a proprietary product. The app follows Iced's Elm
//! architecture, which maps cleanly onto the existing
//! `starlab_client::core::*Manager` backend:
//!
//! * the old Slint global `AppState` becomes the [`State`] model,
//! * Slint `callback`s become [`Message`] variants handled in
//!   [`State::update`],
//! * each `.slint` screen/component becomes an Iced `view` helper
//!   returning `Element<Message>`,
//! * the async core managers push state through [`UICallback`] →
//!   [`UiEvent`] over an mpsc channel, drained by a [`Subscription`]
//!   that turns each event into [`Message::Ui`].

mod core_adapter;
mod ui_callback;

use std::sync::{Arc, Mutex as StdMutex};

use iced::futures::stream;
use iced::widget::{Column, Space, button, column, container, row, scrollable, text, text_input};
use iced::{clipboard, Background, Border, Color, Element, Length, Subscription, Task, Theme};

use core_adapter::CoreAdapter;
use starlab_client::core::{ConnectionInfo, SessionInfo, SessionStatus, SigningState};
use ui_callback::UiEvent;

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

/// Which right-panel tab is showing (mirrors the old Slint `TabWidget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Operations,
    Logs,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAction {
    Connect,
    CreateWallet,
    JoinWallet,
    ImportWallet,
    ExportWallet,
    Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFlow {
    Create,
    Join,
}

#[derive(Debug, Clone)]
pub enum Message {
    // --- UI events pushed from the async core ---
    Ui(UiEvent),

    // --- Navigation / input ---
    TabSelected(Tab),
    WalletFlowSelected(WalletFlow),
    NewWalletNameChanged(String),
    KeystorePasswordChanged(String),
    WsUrlChanged(String),
    SignalRoomChanged(String),
    GenerateSignalRoom,
    CopyDeviceId,
    CopyRoomId,
    CopySignalUrl,
    CopyInviteId,
    SignHexChanged(String),
    SignChainChanged(String),
    JoinSessionIdChanged(String),
    WalletSelected(usize),
    /// Switch the displayed BIP-44 account — addresses are re-derived
    /// locally in the view from the wallet's group key (no async hop).
    SelectAccount(u32),
    /// Reveal one more account in the picker (the `＋` button).
    AddAccount,

    // --- Actions (were Slint callbacks) ---
    ConnectWebsocket,
    CreateWallet,
    ImportWallet,
    ExportWallet,
    CreateSession,
    JoinSession,
    LeaveSession,
    RefreshSessions,
    ToggleOfflineMode,
    StartDkg,
    AbortDkg,
    SignMessage,
    ApproveSigning,
    RejectSigning,
    ExportToSdCard,
    ImportFromSdCard,
    ClearSdCard,

    /// Result of a fire-and-forget async action (the core reports the
    /// real outcome via `Ui` events; this just logs failures).
    ActionDone(Result<(), String>),
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// The Iced model — formerly the Slint global `AppState`.
pub struct State {
    adapter: Arc<CoreAdapter>,

    // Connection state
    websocket_connected: bool,
    webrtc_connected: bool,
    mesh_connections: Vec<ConnectionInfo>,
    operation_mode: String,

    // Wallet state (grouped multi-chain view: one entry per wallet_id)
    wallets: Vec<crate::ui_callback::WalletView>,
    active_wallet_index: usize,
    has_keystore: bool,
    /// The BIP-44 account whose addresses are displayed (account 0 is the
    /// default identity; the root group-key address is never shown).
    selected_account: u32,
    /// Highest account index the picker offers; `＋` reveals one more.
    max_account: u32,

    // Session state
    available_sessions: Vec<SessionInfo>,
    active_session: Option<SessionInfo>,

    // DKG state
    dkg_active: bool,
    ceremony_open: bool,
    dkg_current_round: u8,
    dkg_progress: f32,

    // Offline state
    offline_enabled: bool,
    sd_card_detected: bool,

    // Signing state
    has_signing_request: bool,
    signing_request_id: String,
    signing_message_preview: String,
    signing_chain: String,
    signing_label: String,
    signing_state: String,
    last_signature: String,

    // UI chrome
    device_id: String,
    status_message: String,
    pending_action: Option<PendingAction>,
    log_messages: Vec<String>,
    active_tab: Tab,
    wallet_flow: WalletFlow,

    // Input fields
    new_wallet_name: String,
    dkg_password: String,
    ws_url: String,
    signal_room: String,
    sign_hex: String,
    sign_chain: String,
    join_session_id: String,
}

impl State {
    fn new() -> (Self, Task<Message>) {
        // Build the UICallback → UI bridge channel. The sender goes into
        // the CoreAdapter (handed to NativeUICallback); the receiver is
        // stashed for the subscription to pull out exactly once.
        let (ui_tx, ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
        BRIDGE_RX.lock().expect("bridge mutex").replace(ui_rx);

        let device_id =
            std::env::var("MPC_DEVICE_ID").unwrap_or_else(|_| "native-node-001".to_string());

        // Keystore lives alongside the TUI's (~/.frost_keystore).
        let keystore_path = format!(
            "{}/.frost_keystore",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        );

        // Signal server. Env vars remain supported for automation, but the
        // desktop UI owns the room by default so users do not need shell setup.
        let signal_input =
            std::env::var("MPC_SIGNAL_SERVER").unwrap_or_else(|_| "wss://panda.qzz.io".to_string());
        let (signal_base, room_from_url) = split_signal_room(&signal_input);
        let signal_room = std::env::var("MPC_ROOM")
            .ok()
            .filter(|room| !room.trim().is_empty())
            .or(room_from_url)
            .unwrap_or_else(generate_room_id);
        let signal_url = signal_url_with_room(&signal_base, &signal_room);

        let curve = std::env::var("MPC_CURVE").unwrap_or_else(|_| "secp256k1".to_string());

        let adapter = Arc::new(CoreAdapter::new(
            ui_tx,
            device_id.clone(),
            keystore_path,
            signal_url.clone(),
            curve,
        ));

        let state = State {
            adapter,
            websocket_connected: false,
            webrtc_connected: false,
            mesh_connections: Vec::new(),
            operation_mode: "online".to_string(),
            wallets: Vec::new(),
            active_wallet_index: 0,
            has_keystore: false,
            selected_account: 0,
            max_account: 2,
            available_sessions: Vec::new(),
            active_session: None,
            dkg_active: false,
            ceremony_open: false,
            dkg_current_round: 0,
            dkg_progress: 0.0,
            offline_enabled: false,
            sd_card_detected: false,
            has_signing_request: false,
            signing_request_id: String::new(),
            signing_message_preview: String::new(),
            signing_chain: String::new(),
            signing_label: String::new(),
            signing_state: "idle".to_string(),
            last_signature: String::new(),
            device_id,
            status_message: "Ready".to_string(),
            pending_action: None,
            log_messages: Vec::new(),
            active_tab: Tab::Operations,
            wallet_flow: WalletFlow::Join,
            new_wallet_name: String::new(),
            dkg_password: String::new(),
            ws_url: signal_base,
            signal_room,
            sign_hex: String::new(),
            sign_chain: "ethereum".to_string(),
            join_session_id: String::new(),
        };

        // Auto-connect to the configured signal server on launch (a wallet
        // should reach its network immediately; the server is set via
        // MPC_SIGNAL_SERVER / MPC_ROOM). The user can still reconnect from the UI.
        (state, Task::done(Message::ConnectWebsocket))
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }

    // -- Subscription: drain the UICallback bridge channel --------------

    fn subscription(&self) -> Subscription<Message> {
        // `Subscription::run` identifies the subscription by the type of
        // the worker fn, so it's spawned exactly once for the app's life.
        // The worker takes the receiver out of the global slot and folds
        // it into a stream of `Message::Ui`.
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
            Message::WalletFlowSelected(flow) => {
                self.wallet_flow = flow;
                Task::none()
            }
            Message::NewWalletNameChanged(v) => {
                self.new_wallet_name = v;
                Task::none()
            }
            Message::KeystorePasswordChanged(v) => {
                self.dkg_password = v;
                Task::none()
            }
            Message::WsUrlChanged(v) => {
                let (base, room) = split_signal_room(&v);
                self.ws_url = base;
                // split_signal_room returns None for a missing or empty room=,
                // so a URL still being typed keeps the previously-set room.
                if let Some(room) = room {
                    self.signal_room = room;
                }
                Task::none()
            }
            Message::SignalRoomChanged(v) => {
                self.signal_room = normalize_room_id(&v);
                Task::none()
            }
            Message::GenerateSignalRoom => {
                self.signal_room = generate_room_id();
                Task::none()
            }
            Message::CopyDeviceId => {
                self.status_message = "Copied device ID".to_string();
                clipboard::write(self.device_id.clone())
            }
            Message::CopyRoomId => {
                self.status_message = "Copied room ID".to_string();
                clipboard::write(self.signal_room.clone())
            }
            Message::CopySignalUrl => {
                let url = signal_url_with_room(&self.ws_url, &self.signal_room);
                self.status_message = "Copied signal URL".to_string();
                clipboard::write(url)
            }
            Message::CopyInviteId => {
                let Some(invite_id) = self.invite_id().map(str::to_string) else {
                    self.status_message = "No active invite yet".to_string();
                    return Task::none();
                };
                self.status_message = "Copied invite ID".to_string();
                clipboard::write(invite_id)
            }
            Message::SignHexChanged(v) => {
                self.sign_hex = v;
                Task::none()
            }
            Message::SignChainChanged(v) => {
                self.sign_chain = v;
                Task::none()
            }
            Message::JoinSessionIdChanged(v) => {
                self.join_session_id = v;
                Task::none()
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

            Message::ConnectWebsocket => {
                if self.pending_action.is_some() {
                    return Task::none();
                }
                if self.signal_room.trim().is_empty() {
                    self.signal_room = generate_room_id();
                }
                let adapter = self.adapter.clone();
                let url = signal_url_with_room(&self.ws_url, &self.signal_room);
                self.status_message = "Connecting to signal server".to_string();
                self.pending_action = Some(PendingAction::Connect);
                action(async move { adapter.connect_websocket(url).await })
            }
            Message::CreateWallet => {
                if self.wallet_busy() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let name = self.new_wallet_name.clone();
                let pw = self.dkg_password.clone();
                self.status_message =
                    "Creating shared wallet. Waiting for other devices to join.".to_string();
                self.pending_action = Some(PendingAction::CreateWallet);
                action(async move {
                    adapter.set_dkg_password(pw);
                    adapter.create_wallet(name).await
                })
            }
            Message::ImportWallet => {
                if self.pending_action.is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let pw = self.dkg_password.clone();
                self.status_message = "Opening wallet import dialog".to_string();
                self.pending_action = Some(PendingAction::ImportWallet);
                action(async move { adapter.import_wallet(pw).await })
            }
            Message::ExportWallet => {
                if self.pending_action.is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let pw = self.dkg_password.clone();
                self.status_message = "Opening wallet export dialog".to_string();
                self.pending_action = Some(PendingAction::ExportWallet);
                action(async move { adapter.export_wallet(pw).await })
            }
            Message::CreateSession => {
                let adapter = self.adapter.clone();
                action(async move { adapter.create_session().await })
            }
            Message::JoinSession => {
                if self.wallet_busy() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let id = self.join_session_id.clone();
                let pw = self.dkg_password.clone();
                self.status_message = "Joining shared wallet ceremony".to_string();
                self.pending_action = Some(PendingAction::JoinWallet);
                action(async move {
                    adapter.set_dkg_password(pw);
                    adapter.join_session(id).await
                })
            }
            Message::LeaveSession => {
                let adapter = self.adapter.clone();
                action(async move { adapter.leave_session().await })
            }
            Message::RefreshSessions => {
                let adapter = self.adapter.clone();
                action(async move { adapter.refresh_sessions().await })
            }
            Message::ToggleOfflineMode => {
                let adapter = self.adapter.clone();
                action(async move { adapter.toggle_offline_mode().await })
            }
            Message::StartDkg => {
                let adapter = self.adapter.clone();
                action(async move { adapter.start_dkg().await })
            }
            Message::AbortDkg => {
                let adapter = self.adapter.clone();
                action(async move { adapter.abort_dkg().await })
            }
            Message::SignMessage => {
                if self.pending_action.is_some() {
                    return Task::none();
                }
                let adapter = self.adapter.clone();
                let hex = self.sign_hex.clone();
                let chain = self.sign_chain.clone();
                self.status_message = "Requesting MPC signature".to_string();
                self.pending_action = Some(PendingAction::Sign);
                action(async move { adapter.request_signing(hex, chain, None).await.map(|_| ()) })
            }
            Message::ApproveSigning => {
                let adapter = self.adapter.clone();
                let id = self.signing_request_id.clone();
                action(async move { adapter.approve_signing(id).await })
            }
            Message::RejectSigning => {
                let adapter = self.adapter.clone();
                let id = self.signing_request_id.clone();
                action(async move { adapter.reject_signing(id).await })
            }
            Message::ExportToSdCard => {
                let adapter = self.adapter.clone();
                // The old UI passed a data_type label per button; the
                // single native "Export" button uses a generic stem.
                action(async move { adapter.export_to_sd_card("export".to_string()).await })
            }
            Message::ImportFromSdCard => {
                let adapter = self.adapter.clone();
                action(async move { adapter.import_from_sd_card().await })
            }
            Message::ClearSdCard => {
                let adapter = self.adapter.clone();
                action(async move { adapter.clear_sd_card().await })
            }

            Message::ActionDone(result) => {
                if let Err(e) = result {
                    self.pending_action = None;
                    tracing::warn!("native action failed: {e}");
                    self.push_log(format!("[ERROR] {e}"));
                    self.status_message = e;
                } else if matches!(
                    self.pending_action,
                    Some(
                        PendingAction::Connect
                            | PendingAction::ImportWallet
                            | PendingAction::ExportWallet
                            | PendingAction::Sign
                            // Create/Join only queue a message to the runner; a
                            // ceremony that fails later emits no event, so waiting
                            // for DkgStatus/WalletsRich could lock the UI forever.
                            | PendingAction::CreateWallet
                            | PendingAction::JoinWallet
                    )
                ) {
                    self.pending_action = None;
                }
                Task::none()
            }
        }
    }

    /// Apply a single UICallback event onto the model.
    fn apply_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::ConnectionStatus { websocket, webrtc } => {
                self.websocket_connected = websocket;
                self.webrtc_connected = webrtc;
                if websocket && self.pending_action == Some(PendingAction::Connect) {
                    self.pending_action = None;
                    self.status_message = "Signal connected".to_string();
                }
            }
            UiEvent::MeshConnections(conns) => self.mesh_connections = conns,
            UiEvent::OperationMode(mode) => {
                self.operation_mode = match mode {
                    starlab_client::core::OperationMode::Online => "online",
                    starlab_client::core::OperationMode::Offline => "offline",
                    starlab_client::core::OperationMode::Hybrid => "hybrid",
                }
                .to_string();
            }
            UiEvent::Wallets(wallets) => {
                // Single-address list (trait callback) — used only as a
                // has-keystore signal; the displayed list comes from WalletsRich.
                self.has_keystore = !wallets.is_empty();
            }
            UiEvent::WalletsRich(wallets) => {
                if !wallets.is_empty() {
                    self.has_keystore = true;
                    if matches!(
                        self.pending_action,
                        Some(PendingAction::CreateWallet | PendingAction::JoinWallet)
                    ) {
                        self.pending_action = None;
                        self.status_message = "Shared wallet ready".to_string();
                    }
                }
                self.wallets = wallets;
            }
            UiEvent::ActiveWallet(i) => self.active_wallet_index = i,
            UiEvent::AvailableSessions(sessions) => self.available_sessions = sessions,
            UiEvent::ActiveSession(session) => self.active_session = session,
            UiEvent::DkgStatus {
                active,
                round,
                progress,
            } => {
                self.dkg_active = active;
                self.dkg_current_round = round;
                self.dkg_progress = progress;
                if active
                    && matches!(
                        self.pending_action,
                        Some(PendingAction::CreateWallet | PendingAction::JoinWallet)
                    )
                {
                    self.pending_action = None;
                    self.status_message = "Wallet ceremony in progress".to_string();
                }
            }
            UiEvent::CeremonyOpen(open) => self.ceremony_open = open,
            UiEvent::DkgParticipants(_participants) => {
                // TODO(iced): render a per-participant round table; for
                // now the DKG progress bar (driven by DkgStatus) suffices.
            }
            UiEvent::OfflineStatus {
                enabled,
                sd_card_detected,
            } => {
                self.offline_enabled = enabled;
                self.sd_card_detected = sd_card_detected;
            }
            UiEvent::SdOperations(_ops) => {
                // TODO(iced): list pending SD operations. Secondary polish.
            }
            UiEvent::SigningRequest(request) => match request {
                Some(r) => {
                    if self.pending_action == Some(PendingAction::Sign) {
                        self.pending_action = None;
                    }
                    self.has_signing_request = true;
                    self.signing_request_id = r.id;
                    self.signing_message_preview = if r.message_hex.len() > 120 {
                        format!("{}…", &r.message_hex[..120])
                    } else {
                        r.message_hex
                    };
                    self.signing_chain = r.chain;
                    self.signing_label = r.display_label.unwrap_or_default();
                }
                None => {
                    self.has_signing_request = false;
                    self.signing_request_id.clear();
                    self.signing_message_preview.clear();
                    self.signing_chain.clear();
                    self.signing_label.clear();
                }
            },
            UiEvent::SigningState(state) => {
                self.signing_state = match state {
                    SigningState::Idle => "idle",
                    SigningState::AwaitingApproval => "awaiting_approval",
                    SigningState::Commitment => "commitment",
                    SigningState::Share => "share",
                    SigningState::Aggregating => "aggregating",
                    SigningState::Complete => "complete",
                    SigningState::Failed(_) => "failed",
                }
                .to_string();
            }
            UiEvent::SigningComplete(sig) => self.last_signature = sig,
            UiEvent::Message {
                log_line,
                status,
                is_error: _,
            } => {
                self.push_log(log_line);
                self.status_message = status;
            }
            UiEvent::Progress(status) => self.status_message = status,
        }
    }

    fn push_log(&mut self, line: String) {
        self.log_messages.push(line);
        let overflow = self.log_messages.len().saturating_sub(100);
        if overflow > 0 {
            self.log_messages.drain(0..overflow);
        }
    }

    /// A wallet action is queued, or the runner still has a ceremony open.
    /// `pending_action` clears as soon as Create/Join is sent, so without
    /// `ceremony_open` the buttons re-enable while waiting for peers and a
    /// second click would start a second ceremony.
    fn wallet_busy(&self) -> bool {
        self.pending_action.is_some() || self.dkg_active || self.ceremony_open
    }

    fn invite_id(&self) -> Option<&str> {
        own_invite_id(
            &self.device_id,
            self.active_session.as_ref(),
            &self.available_sessions,
        )
    }

    // -- View -----------------------------------------------------------

    fn view(&self) -> Element<'_, Message> {
        container(
            column![
                self.header(),
                row![
                    container(self.left_panel()).width(Length::Fixed(320.0)),
                    container(self.right_panel()).width(Length::Fill),
                ]
                .spacing(18)
                .height(Length::Fill),
            ]
            .spacing(18),
        )
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn header(&self) -> Element<'_, Message> {
        let status = if self.websocket_connected {
            "Signal connected"
        } else {
            header_status(&self.status_message)
        };
        let title = column![
            text("Starlab Desktop").size(22),
            text("MPC Wallet").size(12).color(muted()),
        ]
        .spacing(2);

        row![
            title,
            Space::new().width(Length::Fill),
            column![
                text(format!("Device {}", self.device_id)).size(13),
                text(status).size(12).color(if self.websocket_connected {
                    accent()
                } else {
                    muted()
                }),
            ]
            .spacing(2)
            .align_x(iced::Alignment::End),
        ]
        .align_y(iced::Alignment::Center)
        .into()
    }

    fn left_panel(&self) -> Element<'_, Message> {
        scrollable(
            column![
                self.identity_nav_view(),
                self.wallet_nav_view(),
                self.session_nav_view(),
                self.offline_nav_view(),
            ]
            .spacing(12),
        )
        .into()
    }

    fn right_panel(&self) -> Element<'_, Message> {
        let tabs = row![
            tab_button("Operations", Tab::Operations, self.active_tab),
            tab_button("Logs", Tab::Logs, self.active_tab),
            tab_button("Network", Tab::Settings, self.active_tab),
        ]
        .spacing(6);

        let body: Element<'_, Message> = match self.active_tab {
            Tab::Operations => self.operations_tab(),
            Tab::Logs => self.logs_tab(),
            Tab::Settings => self.settings_tab(),
        };

        // The signing confirm "modal" is rendered inline at the top of
        // the right panel when a request is pending (Iced has no native
        // overlay stacking in this layout, so we surface it prominently).
        let mut content = column![tabs, self.dkg_progress_view()].spacing(14);
        if self.has_signing_request {
            content = content.push(self.signing_modal_view());
        }
        content = content.push(body);

        scrollable(content).into()
    }

    // ---- Components (formerly the .slint component files) ----

    fn identity_nav_view(&self) -> Element<'_, Message> {
        let ws = status_dot("WebSocket", self.websocket_connected);
        let rtc = status_dot("WebRTC", self.webrtc_connected);
        let device = compact_row(
            "Device ID",
            &self.device_id,
            button(text("Copy").size(12)).on_press(Message::CopyDeviceId),
        );
        let room_input = row![
            column![
                text("Room ID").size(12).color(muted()),
                text_input("shared room id", &self.signal_room)
                    .on_input(Message::SignalRoomChanged)
                    .width(Length::Fill),
            ]
            .spacing(2)
            .width(Length::Fill),
            button(text("Copy").size(12)).on_press(Message::CopyRoomId),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);
        let mut room_actions =
            iced::widget::Row::new()
                .spacing(8)
                .push(button(text("New").size(12)).on_press(Message::GenerateSignalRoom))
                .push(button(text("URL").size(12)).on_press(Message::CopySignalUrl));
        if !self.websocket_connected {
            room_actions = room_actions.push(
                button(text("Connect").size(12))
                    .on_press_maybe(self.pending_action.is_none().then_some(Message::ConnectWebsocket)),
            );
        }
        let mesh = text(format!(
            "Mesh peers: {} · mode: {}",
            self.mesh_connections.len(),
            self.operation_mode
        ))
        .size(12)
        .color(muted());

        card(
            "Identity",
            column![
                column![ws, rtc, mesh].spacing(6),
                section_divider(),
                device,
                room_input,
                room_actions,
            ]
            .spacing(10)
                .into(),
        )
    }

    fn wallet_nav_view(&self) -> Element<'_, Message> {
        let mut list = Column::new().spacing(6);
        if self.wallets.is_empty() {
            list = list.push(
                text("No wallets — create or import one.")
                    .size(12)
                    .color(muted()),
            );
        } else {
            // BIP-44 account picker: [Account 0] [Account 1] … [＋]. Switching
            // is a pure State change — addresses below re-derive in this view.
            let mut accounts = iced::widget::Row::new().spacing(6);
            for i in 0..=self.max_account {
                let mut b = button(text(format!("Account {i}")).size(11))
                    .on_press(Message::SelectAccount(i));
                b = if i == self.selected_account {
                    b.style(button::primary)
                } else {
                    b.style(button::secondary)
                };
                accounts = accounts.push(b);
            }
            accounts = accounts.push(button(text("＋").size(11)).on_press(Message::AddAccount));
            list = list.push(
                scrollable(accounts).direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::default(),
                )),
            );

            for (i, w) in self.wallets.iter().enumerate() {
                let selected = i == self.active_wallet_index;
                let header = format!("{} · {}", w.name, w.threshold);
                let mut b = button(text(header).size(13))
                    .width(Length::Fill)
                    .on_press(Message::WalletSelected(i));
                b = if selected {
                    b.style(button::primary)
                } else {
                    b.style(button::secondary)
                };
                // One line per chain address of the selected account
                // (ETH/BTC/SOL/Sui), derived from the group key via the
                // engine's account model — never the root group-key address.
                // The BIP-44 path is shown faintly next to each address.
                let mut col = Column::new().spacing(2).push(b);
                for (curve, gk_hex) in &w.keys {
                    let Ok(gk) = hex::decode(gk_hex) else {
                        continue;
                    };
                    let Ok(addrs) = starlab_core::accounts::account_addresses(
                        curve,
                        &gk,
                        self.selected_account,
                    ) else {
                        continue;
                    };
                    for (chain, path, addr) in addrs {
                        col = col.push(
                            row![
                                text(format!("{}  {}", chain, short_addr(&addr)))
                                    .size(11)
                                    .color(muted()),
                                text(path).size(10).color(faint()),
                            ]
                            .spacing(8)
                            .align_y(iced::Alignment::Center),
                        );
                    }
                }
                list = list.push(col);
            }
        }

        let io_row = row![
            button(text("Import").size(12))
                .on_press_maybe(self.pending_action.is_none().then_some(Message::ImportWallet)),
            button(text("Export").size(12))
                .on_press_maybe(
                    (self.has_keystore && self.pending_action.is_none())
                        .then_some(Message::ExportWallet),
                ),
        ]
        .spacing(8);

        card(
            "Wallets",
            column![list, section_divider(), io_row]
                .spacing(10)
                .into(),
        )
    }

    fn offline_nav_view(&self) -> Element<'_, Message> {
        let toggle = button(text(if self.offline_enabled {
            "Disable offline mode"
        } else {
            "Enable offline mode"
        }))
        .on_press(Message::ToggleOfflineMode);

        let detected = text(format!(
            "SD card: {}",
            if self.sd_card_detected {
                "detected"
            } else {
                "not detected"
            }
        ))
        .size(12)
        .color(muted());

        let sd_row = row![
            button(text("Export").size(12)).on_press(Message::ExportToSdCard),
            button(text("Import").size(12)).on_press(Message::ImportFromSdCard),
            button(text("Clear").size(12)).on_press(Message::ClearSdCard),
        ]
        .spacing(8);

        card("Offline", column![toggle, detected, sd_row].spacing(8).into())
    }

    fn session_nav_view(&self) -> Element<'_, Message> {
        let mut list = Column::new().spacing(6);
        if self.available_sessions.is_empty() {
            list = list.push(text("No sessions available.").size(12).color(muted()));
        } else {
            for s in &self.available_sessions {
                let label = format!(
                    "{} · {}/{} · {} · {}",
                    s.session_id,
                    s.threshold.0,
                    s.threshold.1,
                    s.participants.len(),
                    session_status_str(&s.status),
                );
                let join = Message::JoinSessionIdChanged(s.session_id.clone());
                list = list.push(
                    row![
                        text(label).size(12).width(Length::Fill),
                        button(text("Join").size(12)).on_press(join),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
                );
            }
        }

        let active = match &self.active_session {
            Some(s) => text(format!(
                "Active: {} ({})",
                s.session_id,
                session_status_str(&s.status)
            ))
            .size(12)
            .color(accent()),
            None => text("No active session.").size(12).color(muted()),
        };

        let controls = row![
            button(text("Leave").size(12)).on_press(Message::LeaveSession),
            button(text("Refresh").size(12)).on_press(Message::RefreshSessions),
        ]
        .spacing(8);

        card(
            "Sessions",
            column![list, active, section_divider(), controls]
                .spacing(10)
                .into(),
        )
    }

    /// `components/dkg_progress.slint`
    fn dkg_progress_view(&self) -> Element<'_, Message> {
        let header = if self.dkg_active {
            text(format!(
                "DKG in progress — round {} ({:.0}%)",
                self.dkg_current_round,
                self.dkg_progress * 100.0
            ))
            .color(accent())
        } else {
            text("DKG idle").color(muted())
        };

        let session_line = match &self.active_session {
            Some(s) => text(format!(
                "Session {} · {}/{}",
                s.session_id, s.threshold.0, s.threshold.1
            ))
            .size(12)
            .color(muted()),
            None => text("No active DKG session.").size(12).color(muted()),
        };

        let bar = iced::widget::progress_bar(0.0..=1.0, self.dkg_progress);

        let abort = button(text("Abort DKG"))
            .style(button::danger)
            .on_press_maybe(
                (self.dkg_active || self.ceremony_open).then_some(Message::AbortDkg),
            );

        card(
            "Distributed key generation",
            row![
                column![header.size(14), session_line, bar]
                    .spacing(8)
                    .width(Length::Fill),
                abort,
            ]
            .spacing(16)
            .align_y(iced::Alignment::Center)
            .into(),
        )
    }

    fn operations_tab(&self) -> Element<'_, Message> {
        let connected = self.websocket_connected;
        let wallet_ready = !self.wallets.is_empty() || self.has_keystore;
        let can_sign = self.has_keystore && self.signing_state == "idle";
        let is_creating = self.pending_action == Some(PendingAction::CreateWallet);
        let is_joining = self.pending_action == Some(PendingAction::JoinWallet);
        let busy = self.wallet_busy();
        let can_create_wallet = connected && !busy;
        let can_join_wallet = connected && !busy && !self.join_session_id.trim().is_empty();
        let invite_id = self.invite_id();
        let invite_row: Element<'_, Message> = match invite_id {
            Some(id) => row![
                text(format!("Invite ID: {}", short_addr(id)))
                    .size(12)
                    .color(accent())
                    .width(Length::Fill),
                button(text("Copy invite")).on_press(Message::CopyInviteId),
            ]
            .spacing(10)
            .align_y(iced::Alignment::Center)
            .into(),
            None => Space::new().into(),
        };
        let connect_action = if connected {
            None
        } else {
            Some(
                button(text(if self.pending_action == Some(PendingAction::Connect) {
                    "Connecting..."
                } else {
                    "Connect"
                }))
                .on_press_maybe(
                    (self.pending_action != Some(PendingAction::Connect))
                        .then_some(Message::ConnectWebsocket),
                )
                .into(),
            )
        };
        let mut create_tab =
            button(text("Create new shared wallet")).on_press(Message::WalletFlowSelected(WalletFlow::Create));
        let mut join_tab =
            button(text("Join existing shared wallet")).on_press(Message::WalletFlowSelected(WalletFlow::Join));
        if self.wallet_flow == WalletFlow::Create {
            create_tab = create_tab.style(button::primary);
            join_tab = join_tab.style(button::secondary);
        } else {
            create_tab = create_tab.style(button::secondary);
            join_tab = join_tab.style(button::primary);
        }
        let wallet_path: Element<'_, Message> = match self.wallet_flow {
            WalletFlow::Create => column![
                text("Create a new shared wallet").size(15),
                text(if invite_id.is_some() || self.dkg_active {
                    "Share the invite ID with the other devices. Keep this app open while they join."
                } else {
                    "Use this on the first device. This creates the invite that other devices will join."
                })
                .size(12)
                .color(muted()),
                invite_row,
                row![
                    text_input("Wallet name", &self.new_wallet_name)
                        .on_input(Message::NewWalletNameChanged)
                        .width(Length::Fill),
                    button(text(if is_creating {
                        "Creating..."
                    } else {
                        "Create shared wallet"
                    }))
                    .on_press_maybe(can_create_wallet.then_some(Message::CreateWallet)),
                ]
                .spacing(10)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(10)
            .into(),
            WalletFlow::Join => column![
                text("Join a shared wallet").size(15),
                text("Use this on the other devices. Paste the invite ID from the creator.")
                    .size(12)
                    .color(muted()),
                row![
                    text_input("Invite ID", &self.join_session_id)
                        .on_input(Message::JoinSessionIdChanged)
                        .width(Length::Fill),
                    button(text(if is_joining {
                        "Joining..."
                    } else {
                        "Join shared wallet"
                    }))
                    .on_press_maybe(can_join_wallet.then_some(Message::JoinSession)),
                ]
                .spacing(10)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(10)
            .into(),
        };

        card(
            "Start",
            column![
                flow_step(
                    "1",
                    "Connect devices",
                    if connected {
                        "Connected. Devices that use the same room ID can find each other."
                    } else {
                        "Connect before creating or joining a shared wallet."
                    },
                    if connected { "Ready" } else { "Required" },
                    connect_action,
                ),
                section_divider(),
                row![
                    create_tab,
                    join_tab,
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center),
                wallet_path,
                section_divider(),
                flow_step(
                    "2",
                    "Wait for the ceremony",
                    if self.dkg_active {
                        "The wallet ceremony is running. Keep all devices online until it completes."
                    } else if wallet_ready {
                        "Wallet material is available on this device."
                    } else {
                        "After creating or joining, progress appears in the DKG panel above."
                    },
                    if self.dkg_active {
                        "Running"
                    } else if wallet_ready {
                        "Ready"
                    } else {
                        "Pending"
                    },
                    None,
                ),
                section_divider(),
                flow_step(
                    "3",
                    "Sign message",
                    if can_sign {
                        "Enter a message and request an MPC signature from this device."
                    } else {
                        "Signing becomes available after this device has a wallet share."
                    },
                    if can_sign { "Ready" } else { "Blocked" },
                    can_sign
                        .then(|| button(text("Request signing")).on_press(Message::SignMessage).into()),
                ),
            ]
            .spacing(12)
            .into(),
        )
    }

    fn logs_tab(&self) -> Element<'_, Message> {
        let mut col = Column::new().spacing(2);
        if self.log_messages.is_empty() {
            col = col.push(text("No log messages yet.").size(11).color(muted()));
        } else {
            for line in &self.log_messages {
                col = col.push(text(line).size(11).color(faint()));
            }
        }
        card("Logs", scrollable(col).height(Length::Fixed(360.0)).into())
    }

    fn settings_tab(&self) -> Element<'_, Message> {
        let effective_signal_url = signal_url_with_room(&self.ws_url, &self.signal_room);
        let network = card(
            "Network",
            column![
                text("Signal server").size(12).color(muted()),
                text_input("wss://panda.qzz.io", &self.ws_url)
                    .on_input(Message::WsUrlChanged)
                    .width(Length::Fill),
                text("Room ID").size(12).color(muted()),
                row![
                    text_input("room", &self.signal_room)
                        .on_input(Message::SignalRoomChanged)
                        .width(Length::Fill),
                    button(text("New room")).on_press(Message::GenerateSignalRoom),
                    button(text("Copy")).on_press(Message::CopyRoomId),
                    // Reconnecting mid-ceremony would drop the DKG session.
                    button(text("Connect")).on_press_maybe(
                        (!self.websocket_connected).then_some(Message::ConnectWebsocket),
                    ),
                ]
                .spacing(8),
                row![
                    text(format!("URL: {effective_signal_url}"))
                        .size(11)
                        .color(faint())
                        .width(Length::Fill),
                    button(text("Copy URL")).on_press(Message::CopySignalUrl),
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(8)
            .into(),
        );

        let keystore = card(
            "Keystore (encrypted import/export)",
            column![
                text_input("Keystore password", &self.dkg_password)
                    .secure(true)
                    .on_input(Message::KeystorePasswordChanged),
                row![
                    button(text("Import with password…")).on_press(Message::ImportWallet),
                    button(text("Export with password…"))
                        .on_press_maybe(self.has_keystore.then_some(Message::ExportWallet)),
                ]
                .spacing(8),
            ]
            .spacing(8)
            .into(),
        );

        let can_sign = self.has_keystore && self.signing_state == "idle";
        let last_sig: Element<'_, Message> = if self.last_signature.is_empty() {
            Space::new().into()
        } else {
            text(format!(
                "Last signature: {}",
                short_addr(&self.last_signature)
            ))
            .size(11)
            .color(muted())
            .into()
        };
        let signing = card(
            "Sign message (MPC)",
            column![
                text_input("Message hex (0x… or raw hex)", &self.sign_hex)
                    .on_input(Message::SignHexChanged),
                text_input("Chain (ethereum / solana / …)", &self.sign_chain)
                    .on_input(Message::SignChainChanged),
                button(text("Request signing"))
                    .on_press_maybe(can_sign.then_some(Message::SignMessage)),
                last_sig,
            ]
            .spacing(8)
            .into(),
        );

        column![network, keystore, signing].spacing(16).into()
    }

    /// The signing confirm modal (Slint `if has_signing_request`).
    fn signing_modal_view(&self) -> Element<'_, Message> {
        let label: Element<'_, Message> = if self.signing_label.is_empty() {
            Space::new().into()
        } else {
            text(&self.signing_label).size(13).into()
        };

        let awaiting = self.signing_state == "awaiting_approval";
        let approve_label = if awaiting {
            "Approve & Sign"
        } else {
            "Signing…"
        };

        card(
            "Confirm signing request",
            column![
                label,
                text(format!("Chain: {}", self.signing_chain))
                    .size(12)
                    .color(muted()),
                text("Message:").size(12).color(muted()),
                text(&self.signing_message_preview).size(11),
                text(format!("Phase: {}", self.signing_state))
                    .size(11)
                    .color(faint()),
                row![
                    button(text("Reject"))
                        .style(button::danger)
                        .on_press(Message::RejectSigning),
                    Space::new().width(Length::Fill),
                    button(text(approve_label))
                        .style(button::primary)
                        .on_press_maybe(awaiting.then_some(Message::ApproveSigning)),
                ]
                .spacing(12),
            ]
            .spacing(10)
            .into(),
        )
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

/// The invite this device can hand out: a session it proposed. A session we
/// merely joined is someone else's invite, so it is never shown as ours.
fn own_invite_id<'a>(
    device_id: &str,
    active: Option<&'a SessionInfo>,
    available: &'a [SessionInfo],
) -> Option<&'a str> {
    active
        .into_iter()
        .chain(available)
        .find(|session| session.initiator == device_id)
        .map(|session| session.session_id.as_str())
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
// The UICallback → UI bridge
// ---------------------------------------------------------------------------

/// Holds the receiver end of the UICallback channel between `State::new`
/// (which creates it) and `ui_bridge` (the subscription worker that
/// consumes it). A `OnceLock`-style slot would work too, but the
/// subscription closure can't be `FnOnce`-move a captured receiver into a
/// `'static` stream, so we stash it here and take it out on first run.
static BRIDGE_RX: StdMutex<Option<tokio::sync::mpsc::UnboundedReceiver<UiEvent>>> =
    StdMutex::new(None);

/// Subscription worker: turns the mpsc receiver into a `Stream<Message>`.
/// `Subscription::run` calls this once and keeps the resulting stream
/// alive for the whole application lifetime.
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

fn compact_row<'a>(
    label: &'a str,
    value: &'a str,
    action: iced::widget::Button<'a, Message>,
) -> Element<'a, Message> {
    row![
        column![
            text(label).size(12).color(muted()),
            text(value).size(12).color(faint()),
        ]
        .spacing(2)
        .width(Length::Fill),
        action,
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into()
}

fn flow_step<'a>(
    number: &'a str,
    title: &'a str,
    detail: &'a str,
    status: &'a str,
    action: Option<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut content = row![
        container(text(number).size(12))
            .width(Length::Fixed(28.0))
            .height(Length::Fixed(28.0))
            .center_x(Length::Fixed(28.0))
            .center_y(Length::Fixed(28.0))
            .style(step_badge_style),
        column![
            row![
                text(title).size(15),
                Space::new().width(Length::Fill),
                text(status).size(12).color(status_color(status)),
            ]
            .align_y(iced::Alignment::Center),
            text(detail).size(12).color(muted()),
        ]
        .spacing(4)
        .width(Length::Fill),
    ];

    if let Some(action) = action {
        content = content.push(action);
    }

    content
        .spacing(14)
        .align_y(iced::Alignment::Center)
        .into()
}

fn header_status(status: &str) -> &str {
    if status.starts_with("Connecting") {
        "Connecting"
    } else if status.is_empty() || status == "Ready" {
        "Ready"
    } else {
        status
    }
}

fn step_badge_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb8(67, 74, 86))),
        text_color: Some(Color::from_rgb8(238, 241, 247)),
        border: Border {
            width: 1.0,
            radius: 14.0.into(),
            color: Color::from_rgb8(86, 96, 112),
        },
        ..container::Style::default()
    }
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

fn tab_button(label: &str, tab: Tab, active: Tab) -> Element<'_, Message> {
    let mut b = button(text(label)).on_press(Message::TabSelected(tab));
    b = if tab == active {
        b.style(button::primary)
    } else {
        b.style(button::secondary)
    };
    b.into()
}

fn status_dot(label: &str, connected: bool) -> Element<'_, Message> {
    let dot = if connected { "●" } else { "○" };
    let color = if connected { accent() } else { muted() };
    row![
        text(dot).color(color),
        text(format!(
            "{label}: {}",
            if connected {
                "connected"
            } else {
                "disconnected"
            }
        ))
        .size(13),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center)
    .into()
}

fn short_addr(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn session_status_str(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Waiting => "waiting",
        SessionStatus::InProgress => "in_progress",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
    }
}

fn accent() -> Color {
    Color::from_rgb(0.063, 0.725, 0.506) // #10B981
}

fn muted() -> Color {
    Color::from_rgb(0.58, 0.64, 0.72) // #94A3B8
}

fn faint() -> Color {
    Color::from_rgb(0.80, 0.84, 0.88) // #CBD5E1
}

fn status_color(status: &str) -> Color {
    match status {
        "Ready" | "Running" => accent(),
        "Required" => Color::from_rgb8(236, 190, 104),
        "Blocked" => muted(),
        _ => faint(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionInfo, SessionStatus, own_invite_id, split_signal_room};

    fn session(id: &str, initiator: &str) -> SessionInfo {
        SessionInfo {
            session_id: id.to_string(),
            initiator: initiator.to_string(),
            participants: Vec::new(),
            threshold: (2, 3),
            status: SessionStatus::Waiting,
            created_at: String::new(),
        }
    }

    #[test]
    fn joined_session_is_not_shown_as_own_invite() {
        let joined = session("s1", "peer");
        assert_eq!(own_invite_id("me", Some(&joined), &[joined.clone()]), None);
    }

    #[test]
    fn created_session_is_shown_as_own_invite() {
        let created = session("s1", "me");
        assert_eq!(own_invite_id("me", Some(&created), &[]), Some("s1"));
    }

    #[test]
    fn own_announced_session_is_found_among_available() {
        let sessions = [session("s0", "peer"), session("s1", "me")];
        assert_eq!(own_invite_id("me", None, &sessions), Some("s1"));
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
