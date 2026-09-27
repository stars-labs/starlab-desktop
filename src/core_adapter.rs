//! Adapter to integrate TUI node's shared core with native UI

use starlab_client::AppState;
use starlab_client::core::{
    CoreState, SessionInfo, SessionStatus, UICallback, WalletInfo,
    dkg_manager::DkgManager,
    offline_manager::OfflineManager,
    session_manager::SessionManager,
    signing_backend::{ElmSigningBackend, SigningEventSink},
    signing_manager::SigningManager,
    wallet_manager::WalletManager,
};
use starlab_client::elm::headless::HeadlessRunner;
use starlab_client::elm::model::{WalletConfig, WalletMode};
use starlab_client::elm::{Message, Model};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::ui_callback::{NativeUICallback, UiEvent};

/// Default DKG shape for the native "Create wallet" button. The native UI
/// doesn't yet collect threshold/total/curve, so we default to a 2-of-3
/// secp256k1 (Ethereum) wallet — same shape the old placeholder used. The
/// session is announced; real completion needs the other 2 participants to
/// join over the signal server.
const DEFAULT_TOTAL: u16 = 3;
const DEFAULT_THRESHOLD: u16 = 2;

enum RunnerControl {
    Secp256k1(Arc<Mutex<AppState<frost_secp256k1_tr::Secp256K1Sha256TR>>>),
    Ed25519(Arc<Mutex<AppState<frost_ed25519::Ed25519Sha512>>>),
}

impl RunnerControl {
    async fn set_signal_url(&self, signal_url: String) {
        match self {
            Self::Secp256k1(app_state) => {
                app_state.lock().await.signal_server_url = signal_url;
            }
            Self::Ed25519(app_state) => {
                app_state.lock().await.signal_server_url = signal_url;
            }
        }
    }
}

fn spawn_secp256k1_runner<F>(
    device_id: String,
    keystore_path: String,
    signal_url: String,
    on_sync: F,
) -> (UnboundedSender<Message>, RunnerControl)
where
    F: Fn(&Model, Option<&Message>) + Send + 'static,
{
    let app_state = Arc::new(Mutex::new(
        AppState::<frost_secp256k1_tr::Secp256K1Sha256TR>::with_device_id_and_server(
            device_id.clone(),
            signal_url,
        ),
    ));
    let runner = HeadlessRunner::<frost_secp256k1_tr::Secp256K1Sha256TR>::new(
        device_id,
        keystore_path,
        app_state.clone(),
        Box::new(on_sync),
    );
    let tx = runner.sender();
    tokio::spawn(runner.run());
    (tx, RunnerControl::Secp256k1(app_state))
}

fn spawn_ed25519_runner<F>(
    device_id: String,
    keystore_path: String,
    signal_url: String,
    on_sync: F,
) -> (UnboundedSender<Message>, RunnerControl)
where
    F: Fn(&Model, Option<&Message>) + Send + 'static,
{
    let app_state = Arc::new(Mutex::new(
        AppState::<frost_ed25519::Ed25519Sha512>::with_device_id_and_server(
            device_id.clone(),
            signal_url,
        ),
    ));
    let runner = HeadlessRunner::<frost_ed25519::Ed25519Sha512>::new(
        device_id,
        keystore_path,
        app_state.clone(),
        Box::new(on_sync),
    );
    let tx = runner.sender();
    tokio::spawn(runner.run());
    (tx, RunnerControl::Ed25519(app_state))
}

/// Late-bound signing observers fed from the runner's `on_sync`.
type SigningSlot = Arc<std::sync::Mutex<Option<(SigningEventSink, Arc<SigningManager>)>>>;

/// Core adapter that manages all the shared business logic
pub struct CoreAdapter {
    pub state: Arc<CoreState>,
    pub session_manager: Arc<SessionManager>,
    pub dkg_manager: Arc<DkgManager>,
    pub wallet_manager: Arc<WalletManager>,
    pub offline_manager: Arc<OfflineManager>,
    pub signing_manager: Arc<SigningManager>,
    ui_callback: Arc<dyn UICallback>,
    /// Sender into the headless Elm runner — the REAL backend for
    /// connect / create-wallet / join-session (the managers above remain
    /// in place for the not-yet-ported features: signing, SD-card, etc.).
    runner_tx: UnboundedSender<Message>,
    /// Mutable runner configuration that `ReconnectWebSocket` reads.
    runner_control: RunnerControl,
    /// Keystore password used to encrypt this device's share at DKG time.
    /// Set from the UI's "Keystore password" field before create/join.
    dkg_password: Arc<std::sync::Mutex<String>>,
}

/// Map the current FROST DKG phase to a (round, 0.0..=1.0 progress) pair for
/// the progress bar. Mirrors the percentages the engine logs at each transition.
fn dkg_round_progress(round: &starlab_client::elm::message::DKGRound) -> (u8, f32) {
    use starlab_client::elm::message::DKGRound::*;
    match round {
        Initialization => (0, 0.10),
        WaitingForParticipants => (0, 0.20),
        Round1 => (1, 0.40),
        Round2 => (2, 0.65),
        Finalization => (2, 0.85),
        Complete => (2, 1.0),
    }
}

/// Group the model's per-curve wallet entries by `wallet_id`, carrying each
/// curve's GROUP KEY (not addresses). A unified wallet has two metadata
/// entries (one per curve) under one id, so it ends up with both keys in a
/// single row. The view layer derives the displayed addresses per BIP-44
/// account from these keys via `starlab_core::accounts::account_addresses`
/// — the root group-key address is never derived for display.
fn rich_wallets(model: &Model) -> Vec<crate::ui_callback::WalletView> {
    use crate::ui_callback::WalletView;
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, WalletView> = BTreeMap::new();
    for m in &model.wallet_state.wallets {
        let view = by_id
            .entry(m.session_id.clone())
            .or_insert_with(|| WalletView {
                id: m.session_id.clone(),
                name: m.display_name().to_string(),
                threshold: format!("{}/{}", m.threshold, m.total_participants),
                keys: Vec::new(),
            });
        view.keys
            .push((m.curve_type.clone(), m.group_public_key.clone()));
    }
    by_id.into_values().collect()
}

/// Map an Elm `Model` into the core `WalletInfo` list the Slint UI renders.
/// The on-disk address isn't stored in metadata (only the group key), so we
/// leave `address` blank for now — the wallet still shows its name/threshold,
/// which is the signal that a real DKG completed and persisted.
fn model_wallets(model: &Model) -> Vec<WalletInfo> {
    model
        .wallet_state
        .wallets
        .iter()
        .map(|m| WalletInfo {
            id: m.session_id.clone(),
            name: m.display_name().to_string(),
            // Primary chain address of ACCOUNT 0 (BIP-44) — never the root
            // group-key address, which is not a displayable identity.
            address: {
                hex::decode(&m.group_public_key)
                    .ok()
                    .and_then(|b| {
                        starlab_core::accounts::account_addresses(&m.curve_type, &b, 0).ok()
                    })
                    .and_then(|addrs| addrs.into_iter().next().map(|(_, _, addr)| addr))
                    .unwrap_or_default()
            },
            balance: String::new(),
            chain: if m.curve_type == "ed25519" {
                "Solana".to_string()
            } else {
                "Ethereum".to_string()
            },
            threshold: format!("{}/{}", m.threshold, m.total_participants),
            participants: m.participants.clone(),
        })
        .collect()
}

fn model_session_info(session: &starlab_client::protocal::signal::SessionInfo) -> SessionInfo {
    SessionInfo {
        session_id: session.session_id.clone(),
        initiator: session.proposer_id.clone(),
        participants: session.participants.clone(),
        threshold: (session.threshold, session.total),
        status: if session.participants.len() >= usize::from(session.total) {
            SessionStatus::InProgress
        } else {
            SessionStatus::Waiting
        },
        created_at: String::new(),
    }
}

impl CoreAdapter {
    /// Create new core adapter with native UI callback + a real headless
    /// Elm backend. `device_id`/`keystore_path`/`signal_url` configure the
    /// runner. Must be called from within a Tokio runtime.
    /// `curve` selects the runner's ciphersuite for this launch:
    /// `"ed25519"` (Solana/Sui/Aptos/NEAR) or anything else ⇒ secp256k1
    /// (Ethereum-family + Bitcoin). Like the CLI `serve`, a single native
    /// instance is one curve; launch again with a different curve for the other
    /// family.
    pub fn new(
        ui_tx: UnboundedSender<UiEvent>,
        device_id: String,
        keystore_path: String,
        signal_url: String,
        curve: String,
    ) -> Self {
        let state = Arc::new(CoreState::new());
        // Keep a raw sender for events that aren't on the `UICallback` trait
        // (the multi-chain WalletsRich list — the trait's update_wallets is
        // single-address, and `ui_callback` below is a `dyn` trait object).
        let ui_tx_rich = ui_tx.clone();
        let ui_callback: Arc<dyn UICallback> = Arc::new(NativeUICallback::new(ui_tx));

        // on_sync: mirror the runner's model into the UI after every
        // message. Reuses NativeUICallback's channel pushes; the async
        // pushes are spawned since on_sync itself is synchronous. Curve-agnostic
        // (operates on Model), so it's shared by both spawn fns below.
        let cb_for_sync = ui_callback.clone();
        // Signing backend sink (#94) + the SigningManager: both are
        // constructed AFTER spawn (they need runner_tx), so on_sync reads them
        // through a late-bound slot. The sink resolves ceremonies; the manager
        // turns a peer's signing announce into the approval prompt.
        let signing_slot: SigningSlot = Arc::new(std::sync::Mutex::new(None));
        let signing_for_sync = signing_slot.clone();
        let on_sync = move |model: &Model, msg: Option<&starlab_client::elm::Message>| {
            if let Some(m) = msg {
                if let Ok(guard) = signing_for_sync.lock() {
                    if let Some((sink, manager)) = guard.as_ref() {
                        sink.observe(m);
                        manager.observe(model, m);
                    }
                }
            }
            let cb = cb_for_sync.clone();
            let wallets = model_wallets(model);
            let active_session = model.active_session.as_ref().map(model_session_info);
            let available_sessions = model
                .session_invites
                .iter()
                .map(model_session_info)
                .collect::<Vec<_>>();
            // Multi-chain wallet list straight down the channel (not a trait method).
            let _ = ui_tx_rich.send(UiEvent::WalletsRich(rich_wallets(model)));
            let _ = ui_tx_rich.send(UiEvent::CeremonyOpen(ceremony_open(model)));
            let connected = model.network_state.connected;
            // Real DKG progress from the model (not a hardcoded 50%): active
            // tracks `dkg_in_progress` (flips false on finalize/abort, so the
            // bar resets instead of sticking), round + percent come from the
            // current `dkg_round` phase.
            // `Complete` means the wallet finalized — show idle even if the
            // engine hasn't flipped `dkg_in_progress` back to false on this
            // finalize path (otherwise the bar sticks at 100% "in progress").
            let dkg_done = matches!(
                model.wallet_state.dkg_round,
                starlab_client::elm::message::DKGRound::Complete
            );
            let active = model.wallet_state.dkg_in_progress && !dkg_done;
            // Zero the bar when idle (otherwise the Initialization=10% mapping
            // leaves a stub bar showing under "DKG idle").
            let (round, progress) = if active {
                dkg_round_progress(&model.wallet_state.dkg_round)
            } else {
                (0, 0.0)
            };
            tokio::spawn(async move {
                cb.update_wallets(wallets).await;
                cb.update_active_session(active_session).await;
                cb.update_available_sessions(available_sessions).await;
                cb.update_connection_status(connected, false).await;
                cb.update_dkg_status(active, round, progress).await;
            });
        };
        let (runner_tx, runner_control) = if curve == "ed25519" {
            spawn_ed25519_runner(device_id.clone(), keystore_path, signal_url, on_sync)
        } else {
            // "unified" and "secp256k1" both spawn on the secp256k1 runner; the
            // generic `C` DKG fields are unused on the unified path (UnifiedDkg
            // lives in app_state.unified_dkg).
            spawn_secp256k1_runner(device_id.clone(), keystore_path, signal_url, on_sync)
        };
        // Unified mode = one ceremony → both curves (ETH+BTC + SOL+Sui in one
        // wallet). Flip the model into unified mode like the CLI's `--curve unified`.
        if curve == "unified" {
            let _ = runner_tx
                .send(starlab_client::elm::message::Message::SetUnifiedMode { unified: true });
        }

        Self {
            session_manager: Arc::new(SessionManager::new(state.clone(), ui_callback.clone())),
            dkg_manager: Arc::new(DkgManager::new(state.clone(), ui_callback.clone())),
            wallet_manager: Arc::new(WalletManager::new(state.clone(), ui_callback.clone())),
            offline_manager: Arc::new(OfflineManager::new(state.clone(), ui_callback.clone())),
            signing_manager: {
                // Real FROST signing (#94): SigningManager drives the SAME elm
                // loop the TUI/CLI use, via the backend over runner_tx.
                let (backend, sink) = ElmSigningBackend::new(runner_tx.clone());
                let manager = Arc::new(
                    SigningManager::new(state.clone(), ui_callback.clone()).with_backend(backend),
                );
                *signing_slot.lock().unwrap() = Some((sink, manager.clone()));
                manager
            },
            state,
            ui_callback,
            runner_tx,
            runner_control,
            dkg_password: Arc::new(std::sync::Mutex::new(String::new())),
        }
    }

    /// Set the password used to encrypt this device's key share when the
    /// next create/join DKG runs. Called from the UI before create/join.
    pub fn set_dkg_password(&self, password: String) {
        if let Ok(mut p) = self.dkg_password.lock() {
            *p = password;
        }
    }

    fn dkg_password(&self) -> String {
        self.dkg_password
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Create a new signing request. Typically called from a
    /// "Sign Message" button in Settings; opens the confirm modal
    /// via `UICallback::update_signing_request`. Returns the
    /// request id so the caller can pair approve/reject later.
    pub async fn request_signing(
        &self,
        message_hex: String,
        chain: String,
        display_label: Option<String>,
    ) -> Result<String, String> {
        self.signing_manager
            .request_signing(message_hex, chain, display_label)
            .await
            .map_err(|e| e.to_string())
    }

    /// User approved the pending signing request from the confirm
    /// modal. Runs the REAL FROST ceremony (commitment / share / aggregate
    /// over the mesh) via the SigningBackend (#94): a request this device made
    /// announces a new ceremony; a peer's request joins that peer's session. The share password is
    /// the one the user set for this device's keystore (same field the DKG
    /// flow uses); it goes to the backend and is never stored beyond that.
    pub async fn approve_signing(&self, request_id: String) -> Result<(), String> {
        let password = self.dkg_password();
        if password.is_empty() {
            return Err("set the wallet password first (same one used at create/join)".to_string());
        }
        self.signing_manager
            .approve_and_sign(&request_id, password)
            .await
            .map(|_sig| ())
            .map_err(|e| e.to_string())
    }

    /// User rejected the pending signing request (a peer's request is
    /// declined in the engine, dropping its session invite).
    pub async fn reject_signing(&self, request_id: String) -> Result<(), String> {
        self.signing_manager
            .reject(&request_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// Export an artefact to a user-chosen SD-card directory.
    ///
    /// Opens an rfd folder-picker; the caller's `data_type` is used
    /// as the filename stem (e.g. "dkg_round1", "signing_share").
    /// The actual bytes written are a placeholder until the core
    /// wires real DKG / signing artefacts out through
    /// `OfflineDataPackage` — see the native-node README "Next
    /// steps" #2. This commit ships the UI side so the buttons are
    /// live.
    pub async fn export_to_sd_card(&self, data_type: String) -> Result<(), String> {
        let Some(handle) = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .set_title("Select SD card directory")
                .pick_folder()
        })
        .await
        .map_err(|e| e.to_string())?
        else {
            self.ui_callback
                .show_message("SD-card export cancelled".to_string(), false)
                .await;
            return Ok(());
        };

        let sd_dir = handle.to_path_buf();
        let filename = format!("{}_{}.json", data_type, chrono::Utc::now().timestamp());
        let target = sd_dir.join("mpc_wallet_export").join(&filename);

        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        // Placeholder content — swap for a real OfflineDataPackage
        // once the elm Message loop exposes its artefacts to core.
        let placeholder = serde_json::json!({
            "placeholder": true,
            "data_type": data_type,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "note": "native-node SD export — real artefact pending FROST hookup"
        });
        tokio::fs::write(&target, serde_json::to_vec_pretty(&placeholder).unwrap())
            .await
            .map_err(|e| e.to_string())?;

        self.ui_callback
            .show_message(
                format!("Wrote placeholder {} to {}", data_type, target.display()),
                false,
            )
            .await;
        Ok(())
    }

    /// Read SD-card artefacts from a user-chosen directory.
    ///
    /// Delegates to `OfflineManager::import_from_sd_card` after
    /// temporarily redirecting its path — since `OfflineManager`
    /// reads its `sd_card_path` field (set at construction), we
    /// can't override per-call yet. Until that setter lands, this
    /// handler just opens the folder picker to confirm the user
    /// knows where their SD card is mounted, then delegates.
    pub async fn import_from_sd_card(&self) -> Result<(), String> {
        let Some(handle) = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .set_title("Select SD card directory to import from")
                .pick_folder()
        })
        .await
        .map_err(|e| e.to_string())?
        else {
            self.ui_callback
                .show_message("SD-card import cancelled".to_string(), false)
                .await;
            return Ok(());
        };

        let sd_dir = handle.to_path_buf();
        let import_subdir = sd_dir.join("mpc_wallet_import");
        if !import_subdir.exists() {
            self.ui_callback
                .show_message(
                    format!("No mpc_wallet_import/ directory under {}", sd_dir.display()),
                    true,
                )
                .await;
            return Ok(());
        }

        // Enumerate + surface count via the UI. Real parse flow
        // would construct OfflineDataPackage values and feed them
        // into the elm handlers — deferred to Next step #2.
        let mut count = 0usize;
        let mut entries = tokio::fs::read_dir(&import_subdir)
            .await
            .map_err(|e| e.to_string())?;
        while let Some(_entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            count += 1;
        }

        self.ui_callback
            .show_message(
                format!(
                    "Found {count} SD-card artefacts in {}",
                    import_subdir.display()
                ),
                false,
            )
            .await;
        Ok(())
    }

    /// Clear SD-card MPC wallet directories from a user-chosen
    /// folder. Same caveat as export/import re: OfflineManager's
    /// fixed path — this variant operates on the user-picked path
    /// directly.
    pub async fn clear_sd_card(&self) -> Result<(), String> {
        let Some(handle) = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .set_title("Select SD card directory to clear")
                .pick_folder()
        })
        .await
        .map_err(|e| e.to_string())?
        else {
            self.ui_callback
                .show_message("SD-card clear cancelled".to_string(), false)
                .await;
            return Ok(());
        };

        let sd_dir = handle.to_path_buf();
        let confirmed = self
            .ui_callback
            .request_confirmation(format!(
                "Clear mpc_wallet_* directories under {}?",
                sd_dir.display()
            ))
            .await;
        if !confirmed {
            return Ok(());
        }

        for sub in ["mpc_wallet_export", "mpc_wallet_import"] {
            let p = sd_dir.join(sub);
            if p.exists() {
                tokio::fs::remove_dir_all(&p)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }

        self.state.pending_sd_operations.lock().await.clear();
        self.ui_callback.update_sd_operations(Vec::new()).await;
        self.ui_callback
            .show_message(
                format!("Cleared SD-card data under {}", sd_dir.display()),
                false,
            )
            .await;
        Ok(())
    }

    /// Connect to WebSocket server.
    pub async fn connect_websocket(&self, url: String) -> Result<(), String> {
        let url = url.trim().to_string();
        if url.is_empty() {
            return Err("signal server URL is empty".to_string());
        }

        // The shared reconnect command reads the URL from AppState, so update
        // it first. This lets the desktop UI change room/server without
        // requiring a process restart or environment variables.
        self.runner_control.set_signal_url(url).await;
        self.runner_tx
            .send(Message::TriggerReconnect)
            .map_err(|e| e.to_string())
    }

    /// Create a new wallet via a REAL FROST DKG. Announces a session on the
    /// signal server and runs the ceremony once the other participants join;
    /// on completion the encrypted share is persisted to the keystore and the
    /// wallet appears in the list (under `name`). `name` is the local display
    /// label. Defaults to {DEFAULT_THRESHOLD}-of-{DEFAULT_TOTAL} secp256k1.
    pub async fn create_wallet(&self, name: String) -> Result<(), String> {
        let label = name.trim().to_string();
        let config = WalletConfig {
            name: if label.is_empty() {
                "Wallet".to_string()
            } else {
                label.clone()
            },
            total_participants: DEFAULT_TOTAL,
            threshold: DEFAULT_THRESHOLD,
            mode: WalletMode::Online,
        };
        self.runner_tx
            .send(Message::HeadlessCreateWallet {
                config,
                password: self.dkg_password(),
                label,
            })
            .map_err(|e| e.to_string())
    }

    /// Import a keystore from disk. Opens a native file-picker for
    /// the `.dat` path, then passes the user-supplied password to
    /// `WalletManager::import_wallet` for decryption. Pass `""` if
    /// the keystore is unencrypted.
    pub async fn import_wallet(&self, password: String) -> Result<(), String> {
        // `rfd::AsyncFileDialog` is async-friendly but its await
        // point runs on the GUI thread; keep this on tokio's
        // blocking scheduler to avoid blocking the Slint event loop.
        let Some(handle) = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .add_filter("MPC keystore", &["dat", "json"])
                .set_title("Import MPC keystore")
                .pick_file()
        })
        .await
        .map_err(|e| e.to_string())?
        else {
            self.ui_callback
                .show_message("Import cancelled".to_string(), false)
                .await;
            return Ok(());
        };

        let path = handle.to_string_lossy().into_owned();
        let msg = if password.is_empty() {
            format!("Importing keystore from {path} (no password)...")
        } else {
            format!("Importing keystore from {path}...")
        };
        self.ui_callback.show_message(msg, false).await;

        self.wallet_manager
            .import_wallet(path, password)
            .await
            .map_err(|e| e.to_string())
    }

    /// Export the active wallet to a keystore file. Opens a native
    /// save dialog for the destination path; the user-supplied
    /// password is used to encrypt the output. Pass `""` to write
    /// an unencrypted keystore.
    pub async fn export_wallet(&self, password: String) -> Result<(), String> {
        let Some(handle) = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .add_filter("MPC keystore", &["dat"])
                .set_title("Export MPC keystore")
                .set_file_name("mpc-wallet.dat")
                .save_file()
        })
        .await
        .map_err(|e| e.to_string())?
        else {
            self.ui_callback
                .show_message("Export cancelled".to_string(), false)
                .await;
            return Ok(());
        };

        let path = handle.to_string_lossy().into_owned();

        // Export the currently-active wallet. CoreState tracks the
        // active index alongside the wallet list.
        let active_index = *self.state.active_wallet_index.lock().await;
        let msg = if password.is_empty() {
            format!("Exporting wallet to {path} (unencrypted)...")
        } else {
            format!("Exporting wallet to {path}...")
        };
        self.ui_callback.show_message(msg, false).await;

        self.wallet_manager
            .export_wallet(active_index, path, password)
            .await
            .map_err(|e| e.to_string())
    }

    /// Create a new session
    pub async fn create_session(&self) -> Result<(), String> {
        // Get device ID (would be from config in real app)
        let device_id = "native-node-001".to_string();

        self.session_manager
            .create_session(device_id, 2, 3)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Join an existing session
    pub async fn join_session(&self, session_id: String) -> Result<(), String> {
        // Real join via the headless Elm runner: contributes this device's
        // share to the DKG (or signing) ceremony for `session_id`, then
        // persists the resulting key share to the keystore.
        self.runner_tx
            .send(Message::HeadlessJoinSession {
                session_id,
                password: self.dkg_password(),
                label: String::new(),
            })
            .map_err(|e| e.to_string())
    }

    /// Leave current session
    pub async fn leave_session(&self) -> Result<(), String> {
        let device_id = "native-node-001".to_string();

        self.session_manager
            .leave_session(device_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// Refresh available sessions
    pub async fn refresh_sessions(&self) -> Result<(), String> {
        self.session_manager
            .refresh_sessions()
            .await
            .map_err(|e| e.to_string())
    }

    /// Toggle offline mode
    pub async fn toggle_offline_mode(&self) -> Result<(), String> {
        self.offline_manager
            .toggle_offline_mode()
            .await
            .map_err(|e| e.to_string())
    }

    /// Start DKG process
    pub async fn start_dkg(&self) -> Result<(), String> {
        // Get active session
        let session = self
            .session_manager
            .get_active_session()
            .await
            .ok_or_else(|| "No active session".to_string())?;

        // Start DKG with session participants
        self.dkg_manager
            .start_dkg(session.threshold.0, session.participants)
            .await
            .map_err(|e| e.to_string())
    }

    /// Abort the wallet ceremony. The runner owns the DKG state, so cancel
    /// there: it clears `creating_wallet` / `joining_session`, which is what
    /// unlocks Create/Join again (including after a failed ceremony).
    pub async fn abort_dkg(&self) -> Result<(), String> {
        self.runner_tx
            .send(Message::CancelDKG)
            .map_err(|e| e.to_string())
    }
}

/// A wallet ceremony is open on this device, as creator or joiner.
fn ceremony_open(model: &Model) -> bool {
    model.wallet_state.creating_wallet.is_some() || model.wallet_state.joining_session.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use starlab_client::protocal::signal::{SessionInfo as SignalSession, SessionType};
    use std::time::Duration;
    use tokio::sync::watch;

    /// Spawn a real runner (unreachable signal server) that reports
    /// `ceremony_open` after every update.
    fn spawn_runner() -> (UnboundedSender<Message>, watch::Receiver<bool>, std::path::PathBuf) {
        let keystore = std::env::temp_dir().join(format!("starlab-test-{}", uuid::Uuid::new_v4()));
        let (flag_tx, flag_rx) = watch::channel(false);
        let (tx, _control) = spawn_secp256k1_runner(
            "test-device".to_string(),
            keystore.to_string_lossy().into_owned(),
            "ws://127.0.0.1:9".to_string(),
            move |model: &Model, _| {
                let _ = flag_tx.send(ceremony_open(model));
            },
        );
        (tx, flag_rx, keystore)
    }

    async fn wait_for(rx: &mut watch::Receiver<bool>, want: bool) {
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|v| *v == want))
            .await
            .unwrap_or_else(|_| panic!("ceremony_open never became {want}"))
            .expect("runner dropped");
    }

    #[tokio::test]
    async fn creator_ceremony_opens_on_create_and_closes_on_cancel() {
        let (tx, mut open, keystore) = spawn_runner();
        tx.send(Message::HeadlessCreateWallet {
            config: WalletConfig {
                name: "w".to_string(),
                total_participants: DEFAULT_TOTAL,
                threshold: DEFAULT_THRESHOLD,
                mode: WalletMode::Online,
            },
            password: "pw".to_string(),
            label: "w".to_string(),
        })
        .unwrap();
        wait_for(&mut open, true).await;

        tx.send(Message::CancelDKG).unwrap();
        wait_for(&mut open, false).await;
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn joiner_ceremony_opens_on_join_and_closes_on_cancel() {
        let (tx, mut open, keystore) = spawn_runner();
        tx.send(Message::SessionDiscovered {
            session: SignalSession {
                session_id: "s1".to_string(),
                proposer_id: "peer".to_string(),
                total: 2,
                threshold: 2,
                participants: vec!["peer".to_string()],
                session_type: SessionType::DKG,
                curve_type: "secp256k1".to_string(),
                coordination_type: "online".to_string(),
                signing_message_hex: None,
            },
        })
        .unwrap();
        tx.send(Message::HeadlessJoinSession {
            session_id: "s1".to_string(),
            password: "pw".to_string(),
            label: String::new(),
        })
        .unwrap();
        wait_for(&mut open, true).await;

        tx.send(Message::CancelDKG).unwrap();
        wait_for(&mut open, false).await;
        let _ = std::fs::remove_dir_all(keystore);
    }

    /// A real adapter (unreachable signal server) for device `me` holding
    /// wallet `w1`, plus the receiving end of its UI channel.
    fn adapter_holding_w1() -> (
        CoreAdapter,
        tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
        std::path::PathBuf,
    ) {
        let keystore = std::env::temp_dir().join(format!("starlab-test-{}", uuid::Uuid::new_v4()));
        let (ui_tx, ui_rx) = tokio::sync::mpsc::unbounded_channel();
        let adapter = CoreAdapter::new(
            ui_tx,
            "me".to_string(),
            keystore.to_string_lossy().into_owned(),
            "ws://127.0.0.1:9".to_string(),
            "secp256k1".to_string(),
        );
        let wallet = serde_json::from_value(serde_json::json!({
            "session_id": "w1",
            "device_id": "me",
            "curve_type": "secp256k1",
            "threshold": 2,
            "total_participants": 3,
            "participant_index": 2,
            "group_public_key": "",
            "created_at": "",
            "last_modified": "",
        }))
        .unwrap();
        adapter
            .runner_tx
            .send(Message::WalletsLoaded {
                wallets: vec![wallet],
            })
            .unwrap();
        (adapter, ui_rx, keystore)
    }

    fn peer_signing_announce() -> Message {
        Message::SessionDiscovered {
            session: SignalSession {
                session_id: "sign-1".to_string(),
                proposer_id: "peer".to_string(),
                total: 3,
                threshold: 2,
                participants: vec!["peer".to_string(), "me".to_string()],
                session_type: SessionType::Signing {
                    wallet_name: "w1-ethereum-0".to_string(),
                    curve_type: "secp256k1".to_string(),
                    blockchain: "ethereum".to_string(),
                    group_public_key: String::new(),
                },
                curve_type: "secp256k1".to_string(),
                coordination_type: "network".to_string(),
                signing_message_hex: Some("deadbeef".to_string()),
            },
        }
    }

    /// Next `UiEvent::SigningRequest` pushed to the UI (skipping the
    /// per-message state mirrors).
    async fn next_signing_request(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
    ) -> Option<starlab_client::core::SigningRequest> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await.expect("ui channel closed") {
                    UiEvent::SigningRequest(req) => return req,
                    _ => continue,
                }
            }
        })
        .await
        .expect("no SigningRequest event pushed")
    }

    #[tokio::test]
    async fn peer_signing_session_opens_the_approval_prompt() {
        let (adapter, mut ui_rx, keystore) = adapter_holding_w1();
        adapter.runner_tx.send(peer_signing_announce()).unwrap();

        let req = next_signing_request(&mut ui_rx)
            .await
            .expect("a peer's signing session must open the prompt");
        assert_eq!(req.session_id.as_deref(), Some("sign-1"));
        assert_eq!(req.message_hex, "deadbeef");
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn rejecting_a_peer_request_closes_the_prompt_and_drops_the_invite() {
        let (adapter, mut ui_rx, keystore) = adapter_holding_w1();
        adapter.runner_tx.send(peer_signing_announce()).unwrap();
        let req = next_signing_request(&mut ui_rx).await.unwrap();

        adapter.reject_signing(req.id).await.unwrap();
        assert!(next_signing_request(&mut ui_rx).await.is_none());

        // The engine's decline path removes the invite from the session list.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let UiEvent::AvailableSessions(sessions) = ui_rx.recv().await.unwrap()
                    && sessions.iter().all(|s| s.session_id != "sign-1")
                {
                    return;
                }
            }
        })
        .await
        .expect("declined session never left the session list");
        let _ = std::fs::remove_dir_all(keystore);
    }
}
