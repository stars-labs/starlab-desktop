//! Adapter between the Iced UI and the starlab engine.
//!
//! The engine's headless Elm runner is the backend: it owns the signal-server
//! connection, the DKG ceremonies and the keystore. Signing goes through the
//! engine's `SigningManager`, which drives that same runner.

use starlab_client::AppState;
use starlab_client::core::{
    CoreState, UICallback,
    signing_backend::{ElmSigningBackend, SigningEventSink},
    signing_manager::SigningManager,
    wallet_manager::WalletManager,
};
use starlab_client::elm::headless::HeadlessRunner;
use starlab_client::elm::model::{WalletConfig, WalletMode};
use starlab_client::elm::{Message, Model};
use starlab_client::protocal::ecdsa::PrimeSupply;
use starlab_client::protocal::signal::{SessionInfo as SignalSession, SessionType};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::ui_callback::{EcdsaSetup, Invite, NativeUICallback, UiEvent};

/// Shape of every wallet the desktop creates: 2-of-3. The UI states this so
/// users know how many devices to bring.
pub const DEFAULT_TOTAL: u16 = 3;
pub const DEFAULT_THRESHOLD: u16 = 2;

/// Env overrides that skip the native file dialogs (headless / Xvfb runs have
/// no desktop file portal, so the dialog would never open).
const IMPORT_PATH_ENV: &str = "MPC_IMPORT_PATH";
const EXPORT_PATH_ENV: &str = "MPC_EXPORT_PATH";

/// A dialog that has not answered by then is treated as unable to open.
const DIALOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

fn env_path(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|p| !p.trim().is_empty())
}

/// The file path to use: `override_path` when set (from `env_var`), else the
/// native `dialog`'s answer. `Ok(None)` means the user cancelled; a dialog
/// that fails or never opens is an error naming the override.
async fn pick_path<F>(
    override_path: Option<String>,
    env_var: &str,
    dialog: F,
) -> Result<Option<String>, String>
where
    F: FnOnce() -> Option<std::path::PathBuf> + Send + 'static,
{
    if let Some(path) = override_path {
        return Ok(Some(path));
    }
    match tokio::time::timeout(DIALOG_TIMEOUT, tokio::task::spawn_blocking(dialog)).await {
        Ok(Ok(path)) => Ok(path.map(|p| p.to_string_lossy().into_owned())),
        Ok(Err(e)) => Err(format!(
            "The file dialog failed ({e}). Set {env_var} to a file path instead."
        )),
        Err(_) => Err(format!(
            "The file dialog did not open (no desktop file portal?). Set {env_var} to a file \
             path instead."
        )),
    }
}

/// The share files at `path`: the file itself, or every `.json` in a folder
/// (sorted, so imports run in a stable order).
fn share_files(path: &str) -> Result<Vec<String>, String> {
    let p = std::path::Path::new(path);
    if !p.is_dir() {
        return Ok(vec![path.to_string()]);
    }
    let mut files: Vec<String> = std::fs::read_dir(p)
        .map_err(|e| format!("cannot read {path}: {e}"))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|f| f.extension().is_some_and(|ext| ext == "json"))
        .map(|f| f.to_string_lossy().into_owned())
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no .json key-share files in {path}"));
    }
    Ok(files)
}

/// Peers whose WebRTC data channel to this device is open.
fn connected_peers(model: &Model) -> usize {
    model
        .network_state
        .participant_webrtc_status
        .values()
        .filter(|(_, channel)| *channel)
        .count()
}

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

/// Spawn the secp256k1 runner. Its wallets carry an Ethereum key made with
/// threshold ECDSA, which needs Paillier safe primes: `primes` (real ones,
/// generated in the background, unless a test injects fixed ones) starts
/// generating now so they're ready by the time a wallet is set up.
fn spawn_secp256k1_runner<F>(
    device_id: String,
    keystore_path: String,
    signal_url: String,
    primes: PrimeSupply,
    on_sync: F,
) -> (UnboundedSender<Message>, RunnerControl)
where
    F: Fn(&Model, Option<&Message>) + Send + 'static,
{
    let mut state = AppState::<frost_secp256k1_tr::Secp256K1Sha256TR>::with_device_id_and_server(
        device_id.clone(),
        signal_url,
    );
    primes.start();
    state.ecdsa.primes = primes;
    let app_state = Arc::new(Mutex::new(state));
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

/// A wallet setup's FROST rounds are running. The engine also raises
/// `dkg_in_progress` when a *signing* mesh is ready (it reuses the round-1
/// trigger), so only count it while a wallet setup is open — otherwise a
/// co-signer shows "Generating keys" after approving a request.
fn dkg_running(model: &Model) -> bool {
    model.wallet_state.dkg_in_progress && ceremony_open(model)
}

/// The FROST part of the running wallet setup is done (`Complete`) but the
/// wallet isn't finalized yet: the Ethereum (ECDSA) key is being made. The
/// engine clears `creating_wallet` / `joining_session` only on finalize.
fn ecdsa_keygen_running(model: &Model) -> bool {
    ceremony_open(model)
        && matches!(
            model.wallet_state.dkg_round,
            starlab_client::elm::message::DKGRound::Complete
        )
}

/// Tracks how long the prime generator has been working: it starts at
/// launch and again after each wallet setup takes a set.
struct PrimeWatch {
    supply: PrimeSupply,
    since: std::time::Instant,
    was_ready: bool,
    was_keygen: bool,
}

impl PrimeWatch {
    fn new(supply: PrimeSupply) -> Self {
        Self {
            was_ready: supply.is_ready(),
            supply,
            since: std::time::Instant::now(),
            was_keygen: false,
        }
    }

    /// `keygen`: a wallet setup's ECDSA step is running. The generator
    /// starts the next set the moment a setup takes one — which may happen
    /// between two polls — so the clock also restarts when a setup ends.
    fn status(&mut self, keygen: bool) -> EcdsaSetup {
        let ready = self.supply.is_ready();
        if (self.was_ready && !ready) || (self.was_keygen && !keygen && !ready) {
            self.since = std::time::Instant::now(); // a setup took the set
        }
        self.was_ready = ready;
        self.was_keygen = keygen;
        if ready {
            EcdsaSetup::Ready
        } else {
            EcdsaSetup::Preparing {
                elapsed_secs: self.since.elapsed().as_secs(),
            }
        }
    }
}

/// Push this device's ECDSA setup state to the UI once a second.
fn spawn_prime_status(
    supply: PrimeSupply,
    keygen: Arc<std::sync::atomic::AtomicBool>,
    ui_tx: UnboundedSender<UiEvent>,
) {
    tokio::spawn(async move {
        let mut watch = PrimeWatch::new(supply);
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let running = keygen.load(std::sync::atomic::Ordering::Relaxed);
            if ui_tx
                .send(UiEvent::EcdsaSetup(watch.status(running)))
                .is_err()
            {
                return; // app closed
            }
        }
    });
}

/// A new-wallet invite; signing and reshare sessions aren't invites.
fn invite(session: &SignalSession) -> Option<Invite> {
    (session.session_type == SessionType::DKG).then(|| Invite {
        id: session.session_id.clone(),
        proposer: session.proposer_id.clone(),
        participants: session.participants.clone(),
        threshold: session.threshold,
        total: session.total,
    })
}

/// A wallet ceremony is open on this device, as creator or joiner.
fn ceremony_open(model: &Model) -> bool {
    model.wallet_state.creating_wallet.is_some() || model.wallet_state.joining_session.is_some()
}

/// Late-bound signing observers fed from the runner's `on_sync`: the sink
/// resolves ceremonies; the manager turns a peer's signing announce into an
/// approval request.
type SigningSlot = Arc<std::sync::Mutex<Option<(SigningEventSink, Arc<SigningManager>)>>>;

pub struct CoreAdapter {
    signing_manager: Arc<SigningManager>,
    /// Key-share import/export on the same on-disk keystore the runner uses.
    wallet_manager: Arc<WalletManager>,
    runner_tx: UnboundedSender<Message>,
    /// Mutable runner configuration that `TriggerReconnect` reads.
    runner_control: RunnerControl,
}

impl CoreAdapter {
    /// Spawn the engine runner for `curve` ("ed25519", "unified", anything
    /// else ⇒ secp256k1) and bridge its state into `ui_tx`. Like the CLI
    /// `serve`, one desktop instance signs on one curve. Must be called from
    /// within a Tokio runtime.
    pub fn new(
        ui_tx: UnboundedSender<UiEvent>,
        device_id: String,
        keystore_path: String,
        signal_url: String,
        curve: String,
    ) -> Self {
        Self::with_primes(
            ui_tx,
            device_id,
            keystore_path,
            signal_url,
            curve,
            PrimeSupply::background(),
        )
    }

    /// [`Self::new`] with an explicit source of ECDSA safe primes — tests
    /// inject `PrimeSupply::insecure_test_fixed` so a wallet setup doesn't
    /// spend minutes generating them.
    fn with_primes(
        ui_tx: UnboundedSender<UiEvent>,
        device_id: String,
        keystore_path: String,
        signal_url: String,
        curve: String,
        primes: PrimeSupply,
    ) -> Self {
        let ui_callback: Arc<dyn UICallback> = Arc::new(NativeUICallback::new(ui_tx.clone()));

        // The signing backend and manager need runner_tx, so they're built
        // after the spawn and reach on_sync through a late-bound slot.
        let signing_slot: SigningSlot = Arc::new(std::sync::Mutex::new(None));
        let signing_for_sync = signing_slot.clone();
        let ui_tx_for_primes = ui_tx.clone();
        let keygen_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keygen_for_sync = keygen_flag.clone();

        // on_sync: mirror the runner's model into the UI after every message.
        let on_sync = move |model: &Model, msg: Option<&Message>| {
            if let Some(m) = msg
                && let Ok(guard) = signing_for_sync.lock()
                && let Some((sink, manager)) = guard.as_ref()
            {
                sink.observe(m);
                manager.observe(model, m);
            }
            // `Complete` means the wallet finalized — show idle even if the
            // engine hasn't flipped `dkg_in_progress` back on this path.
            let dkg_done = matches!(
                model.wallet_state.dkg_round,
                starlab_client::elm::message::DKGRound::Complete
            );
            let active = dkg_running(model) && !dkg_done;
            let (round, progress) = if active {
                dkg_round_progress(&model.wallet_state.dkg_round)
            } else {
                (0, 0.0)
            };
            let keygen = ecdsa_keygen_running(model);
            keygen_for_sync.store(keygen, std::sync::atomic::Ordering::Relaxed);
            let events = [
                UiEvent::Connected(model.network_state.connected),
                UiEvent::Peers(connected_peers(model)),
                UiEvent::Wallets(rich_wallets(model)),
                UiEvent::Invites(model.session_invites.iter().filter_map(invite).collect()),
                UiEvent::ActiveSession(model.active_session.as_ref().and_then(invite)),
                UiEvent::CeremonyOpen(ceremony_open(model)),
                UiEvent::EcdsaKeygen(keygen),
                UiEvent::DkgStatus {
                    active,
                    round,
                    progress,
                },
            ];
            for event in events {
                let _ = ui_tx.send(event);
            }
        };
        let state = Arc::new(CoreState::new());
        let wallet_manager = Arc::new(
            WalletManager::new(state.clone(), ui_callback.clone())
                .with_keystore(keystore_path.clone(), device_id.clone()),
        );
        let (runner_tx, runner_control) = if curve == "ed25519" {
            let _ = ui_tx_for_primes.send(UiEvent::EcdsaSetup(EcdsaSetup::NotNeeded));
            spawn_ed25519_runner(device_id, keystore_path, signal_url, on_sync)
        } else {
            // "unified" and "secp256k1" both run on the secp256k1 runner;
            // their wallets get the threshold-ECDSA Ethereum key.
            spawn_prime_status(primes.clone(), keygen_flag, ui_tx_for_primes);
            spawn_secp256k1_runner(device_id, keystore_path, signal_url, primes, on_sync)
        };
        // Unified mode = one ceremony → both curves (ETH+BTC + SOL+Sui in one
        // wallet). Flip the model into unified mode like the CLI's `--curve unified`.
        if curve == "unified" {
            let _ = runner_tx.send(Message::SetUnifiedMode { unified: true });
        }

        let (backend, sink) = ElmSigningBackend::new(runner_tx.clone());
        let signing_manager =
            Arc::new(SigningManager::new(state, ui_callback).with_backend(backend));
        *signing_slot.lock().unwrap() = Some((sink, signing_manager.clone()));

        Self {
            signing_manager,
            wallet_manager,
            runner_tx,
            runner_control,
        }
    }

    /// (Re)connect to the signal server at `url` (server + `?room=`).
    pub async fn connect_websocket(&self, url: String) -> Result<(), String> {
        let url = url.trim().to_string();
        if url.is_empty() {
            return Err("signal server URL is empty".to_string());
        }
        // The runner's reconnect reads the URL from AppState, so set it first.
        self.runner_control.set_signal_url(url).await;
        self.runner_tx
            .send(Message::TriggerReconnect)
            .map_err(|e| e.to_string())
    }

    /// Start a new 2-of-3 wallet: announce the invite and run the DKG once the
    /// other devices join. `password` encrypts this device's share.
    pub async fn create_wallet(&self, name: String, password: String) -> Result<(), String> {
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
                password,
                label,
            })
            .map_err(|e| e.to_string())
    }

    /// Join the new-wallet invite `session_id`; `password` encrypts this
    /// device's share.
    pub async fn join_session(&self, session_id: String, password: String) -> Result<(), String> {
        self.runner_tx
            .send(Message::HeadlessJoinSession {
                session_id,
                password,
                label: String::new(),
            })
            .map_err(|e| e.to_string())
    }

    /// Import exported key-share files (encrypted with `password`) into this
    /// device's keystore; the runner then re-reads the keystore so the wallet
    /// shows up. A wallet has one file per key (a secp256k1 wallet: Taproot +
    /// ECDSA), so the picker takes several files, and `MPC_IMPORT_PATH` may
    /// name a file or a folder (every `.json` in it). A cancelled picker is
    /// not an error.
    pub async fn import_share(&self, password: String) -> Result<(), String> {
        let paths = match env_path(IMPORT_PATH_ENV) {
            Some(path) => share_files(&path)?,
            None => {
                let picked = tokio::time::timeout(
                    DIALOG_TIMEOUT,
                    tokio::task::spawn_blocking(|| {
                        rfd::FileDialog::new()
                            .add_filter("Starlab key share", &["json"])
                            .set_title("Import wallet key shares")
                            .pick_files()
                    }),
                )
                .await;
                match picked {
                    Ok(Ok(Some(files))) => files
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect(),
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Err(e)) => {
                        return Err(format!(
                            "The file dialog failed ({e}). Set {IMPORT_PATH_ENV} to a file or \
                             folder instead."
                        ));
                    }
                    Err(_) => {
                        return Err(format!(
                            "The file dialog did not open (no desktop file portal?). Set \
                             {IMPORT_PATH_ENV} to a file or folder instead."
                        ));
                    }
                }
            }
        };
        for path in paths {
            self.import_share_file(path, password.clone()).await?;
        }
        Ok(())
    }

    async fn import_share_file(&self, path: String, password: String) -> Result<(), String> {
        self.wallet_manager
            .import_wallet(path, password)
            .await
            .map_err(|e| e.to_string())?;
        let _ = self.runner_tx.send(Message::ListWallets);
        Ok(())
    }

    /// Export this device's key shares of `wallet_id` — one file per key in
    /// `curves`, `<wallet_id>-<curve>.json`, still encrypted with the wallet
    /// `password` — into a folder: `MPC_EXPORT_PATH` when set, else one
    /// picked in a native folder dialog.
    pub async fn export_shares(
        &self,
        wallet_id: String,
        curves: Vec<String>,
        password: String,
    ) -> Result<(), String> {
        let Some(dir) = pick_path(env_path(EXPORT_PATH_ENV), EXPORT_PATH_ENV, || {
            rfd::FileDialog::new()
                .set_title("Export wallet key shares to a folder")
                .pick_folder()
        })
        .await?
        else {
            return Ok(());
        };
        std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
        for curve in &curves {
            let path = std::path::Path::new(&dir).join(format!("{wallet_id}-{curve}.json"));
            self.export_share_file(
                &wallet_id,
                curve,
                path.to_string_lossy().into_owned(),
                password.clone(),
            )
            .await?;
        }
        Ok(())
    }

    async fn export_share_file(
        &self,
        wallet_id: &str,
        curve: &str,
        path: String,
        password: String,
    ) -> Result<(), String> {
        self.wallet_manager
            .export_wallet(wallet_id, curve, path, password)
            .await
            .map_err(|e| e.to_string())
    }

    /// Cancel the open ceremony: withdraws our invite, or leaves the one we joined.
    pub async fn cancel_ceremony(&self) -> Result<(), String> {
        self.runner_tx
            .send(Message::CancelDKG)
            .map_err(|e| e.to_string())
    }

    /// Sign `message_hex` with the account wallet `wallet_id`
    /// (`<root>-<chain>-<account>`) and wait for the ceremony to finish. The
    /// signature arrives as `UiEvent::SigningComplete`.
    pub async fn sign(
        &self,
        wallet_id: String,
        chain: String,
        message_hex: String,
        password: String,
    ) -> Result<(), String> {
        let request_id = self
            .signing_manager
            .request_signing(wallet_id, message_hex, chain, None)
            .await
            .map_err(|e| e.to_string())?;
        self.approve_signing(request_id, password).await
    }

    /// Approve signing request `request_id` with the wallet password and wait
    /// for the ceremony: a peer's request joins its session as a co-signer.
    pub async fn approve_signing(
        &self,
        request_id: String,
        password: String,
    ) -> Result<(), String> {
        self.signing_manager
            .approve_and_sign(&request_id, password)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Decline a peer's signing request (the engine drops its invite).
    pub async fn reject_signing(&self, request_id: String) -> Result<(), String> {
        self.signing_manager
            .reject(&request_id)
            .await
            .map_err(|e| e.to_string())
    }

    /// Close a signing request whose ceremony failed.
    pub async fn dismiss_signing(&self) -> Result<(), String> {
        self.signing_manager
            .dismiss()
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::watch;

    /// Spawn a real runner (unreachable signal server) that reports
    /// `ceremony_open` after every update.
    fn spawn_runner() -> (
        UnboundedSender<Message>,
        watch::Receiver<bool>,
        std::path::PathBuf,
    ) {
        let keystore = std::env::temp_dir().join(format!("starlab-test-{}", uuid::Uuid::new_v4()));
        let (flag_tx, flag_rx) = watch::channel(false);
        let (tx, _control) = spawn_secp256k1_runner(
            "test-device".to_string(),
            keystore.to_string_lossy().into_owned(),
            "ws://127.0.0.1:9".to_string(),
            insecure_test_primes(0),
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

    /// **INSECURE, tests only**: the published fixture primes (one set per
    /// device) so a wallet setup doesn't spend minutes generating them.
    fn insecure_test_primes(device: usize) -> PrimeSupply {
        let sets: Vec<starlab_core::ecdsa::Primes> =
            serde_json::from_str(include_str!("../testdata/insecure-test-primes.json"))
                .expect("fixture primes");
        PrimeSupply::insecure_test_fixed(sets[device % sets.len()].clone())
    }

    fn entry(id: &str, curve: &str) -> starlab_client::keystore::WalletMetadata {
        starlab_client::keystore::WalletMetadata::new(
            id.to_string(),
            "d".to_string(),
            curve.to_string(),
            2,
            3,
            1,
            format!("{curve}-key"),
        )
    }

    #[test]
    fn every_key_file_of_a_wallet_is_one_row() {
        let mut model = Model::new("d".to_string());
        model.wallet_state.wallets = vec![
            entry("w1", "secp256k1"),
            entry("w1", "secp256k1-ecdsa"),
            entry("w1", "ed25519"),
        ];
        let rows = rich_wallets(&model);
        assert_eq!(rows.len(), 1);
        let curves: Vec<&str> = rows[0].keys.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(curves, ["secp256k1", "secp256k1-ecdsa", "ed25519"]);
    }

    #[test]
    fn ed25519_only_and_two_wallets_group_by_id() {
        let mut model = Model::new("d".to_string());
        model.wallet_state.wallets = vec![
            entry("b", "secp256k1"),
            entry("a", "ed25519"),
            entry("b", "secp256k1-ecdsa"),
        ];
        let rows = rich_wallets(&model);
        assert_eq!(rows.len(), 2);
        let a = rows.iter().find(|w| w.id == "a").unwrap();
        assert_eq!(a.keys.len(), 1, "ed25519-only wallet");
        let b = rows.iter().find(|w| w.id == "b").unwrap();
        assert_eq!(b.keys.len(), 2, "Taproot + ECDSA");
    }

    #[test]
    fn ecdsa_setup_text() {
        assert_eq!(
            EcdsaSetup::Preparing { elapsed_secs: 9 }
                .describe()
                .as_deref(),
            Some("ECDSA setup: preparing safe primes (9s so far, usually 1-5 min)")
        );
        assert_eq!(
            EcdsaSetup::Ready.describe().as_deref(),
            Some("ECDSA setup: ready")
        );
        assert_eq!(EcdsaSetup::NotNeeded.describe(), None);
    }

    #[test]
    fn prime_watch_restarts_the_clock_when_a_setup_takes_the_primes() {
        let fixed = insecure_test_primes(0);
        let mut watch = PrimeWatch::new(fixed);
        assert_eq!(watch.status(false), EcdsaSetup::Ready);

        let background = PrimeSupply::background();
        let mut watch = PrimeWatch::new(background);
        assert_eq!(
            watch.status(false),
            EcdsaSetup::Preparing { elapsed_secs: 0 },
            "not started → still to prepare"
        );
        // A setup ends without the watch ever seeing the set ready: the
        // clock restarts for the next set.
        watch.since -= std::time::Duration::from_secs(300);
        let _ = watch.status(true);
        assert_eq!(
            watch.status(false),
            EcdsaSetup::Preparing { elapsed_secs: 0 }
        );
    }

    #[test]
    fn a_signing_mesh_is_not_a_wallet_setup() {
        let mut model = Model::new("d".to_string());
        model.wallet_state.dkg_in_progress = true; // raised by a signing mesh
        assert!(!dkg_running(&model));
        model.wallet_state.joining_session = Some("s".to_string());
        assert!(dkg_running(&model));
    }

    #[test]
    fn ecdsa_keygen_runs_between_frost_complete_and_finalize() {
        let mut model = Model::new("d".to_string());
        model.wallet_state.joining_session = Some("s".to_string());
        assert!(!ecdsa_keygen_running(&model), "FROST rounds still running");
        model.wallet_state.dkg_round = starlab_client::elm::message::DKGRound::Complete;
        assert!(ecdsa_keygen_running(&model));
        model.wallet_state.joining_session = None; // finalized
        assert!(!ecdsa_keygen_running(&model));
    }

    /// Consume `rx` until an event matches `pick`; panics after 90s.
    async fn next_match<T>(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
        what: &str,
        mut pick: impl FnMut(&UiEvent) -> Option<T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let event = rx.recv().await.expect("adapter dropped");
                if let Some(found) = pick(&event) {
                    return found;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    /// Three desktop adapters on one in-process signal server: create a
    /// 2-of-3 wallet, sign with an account wallet from one device while
    /// another approves the request (the Sign tab and Signature request card
    /// paths), then export a share and import it into a fresh install.
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    #[ignore = "real DKG + signing over loopback WebRTC; run with --ignored"]
    async fn three_devices_create_a_wallet_and_sign() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/?room=e2e-{}",
            listener.local_addr().unwrap(),
            uuid::Uuid::new_v4()
        );
        tokio::spawn(starlab_signal_server::run(listener));

        let mut devices = Vec::new();
        for i in 0..3 {
            let keystore =
                std::env::temp_dir().join(format!("starlab-e2e-{}", uuid::Uuid::new_v4()));
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let adapter = CoreAdapter::with_primes(
                tx,
                format!("device-{i}"),
                keystore.to_string_lossy().into_owned(),
                url.clone(),
                "secp256k1".to_string(),
                insecure_test_primes(i),
            );
            adapter.connect_websocket(url.clone()).await.unwrap();
            next_match(&mut rx, "connection", |e| {
                matches!(e, UiEvent::Connected(true)).then_some(())
            })
            .await;
            devices.push((adapter, rx, keystore, format!("pw-{i}")));
        }

        // Device 0 creates; 1 and 2 join from the invite they see.
        devices[0]
            .0
            .create_wallet("e2e".to_string(), devices[0].3.clone())
            .await
            .unwrap();
        for (adapter, rx, _, password) in devices.iter_mut().skip(1) {
            let invite_id = next_match(rx, "wallet invite", |e| match e {
                UiEvent::Invites(invites) => invites
                    .iter()
                    .find(|i| i.proposer == "device-0")
                    .map(|i| i.id.clone()),
                _ => None,
            })
            .await;
            adapter
                .join_session(invite_id, password.clone())
                .await
                .unwrap();
        }
        // The wallet is listed once FROST AND the ECDSA (Ethereum) key are
        // done: one row holding the Taproot and the ECDSA key.
        let mut wallet = None;
        for (_, rx, _, _) in devices.iter_mut() {
            wallet = Some(
                next_match(rx, "finished wallet", |e| match e {
                    UiEvent::Wallets(wallets) => wallets
                        .first()
                        .filter(|w| w.keys.iter().any(|(c, _)| c == "secp256k1-ecdsa"))
                        .cloned(),
                    _ => None,
                })
                .await,
            );
        }
        let wallet = wallet.expect("three devices");
        let wallet_id = wallet.id.clone();
        let ecdsa_key = wallet
            .keys
            .iter()
            .find(|(c, _)| c == "secp256k1-ecdsa")
            .map(|(_, k)| hex::decode(k).unwrap())
            .unwrap();
        let account1 = starlab_core::accounts::account_addresses("secp256k1-ecdsa", &ecdsa_key, 1)
            .unwrap()
            .remove(0)
            .2;

        // Device 0 signs with account 1 on Ethereum; device 1 approves.
        let (signer, mut signer_rx, signer_keystore, signer_password) = devices.remove(0);
        let account_wallet = format!("{wallet_id}-ethereum-1");
        let signing = tokio::spawn(async move {
            signer
                .sign(
                    account_wallet,
                    "ethereum".to_string(),
                    "48656c6c6f".to_string(),
                    signer_password,
                )
                .await
        });
        let (approver, approver_rx, _, approver_password) = &mut devices[0];
        let request_id = next_match(approver_rx, "signature request", |e| match e {
            UiEvent::SigningRequest(Some(r)) if r.session_id.is_some() => Some(r.id.clone()),
            _ => None,
        })
        .await;
        approver
            .approve_signing(request_id, approver_password.clone())
            .await
            .expect("co-signing succeeded");

        signing.await.unwrap().expect("signing succeeded");
        let signature = next_match(&mut signer_rx, "signature", |e| match e {
            UiEvent::SigningComplete(signature) => Some(signature.clone()),
            _ => None,
        })
        .await;
        // Threshold ECDSA: 65-byte r ‖ s ‖ v that ecrecovers (EIP-191 hash
        // of "Hello") to Ethereum account 1 of the wallet.
        let signature = hex::decode(signature.trim_start_matches("0x")).unwrap();
        assert_eq!(signature.len(), 65);
        let prehash = starlab_client::utils::eth_helper::eip191_hash(b"Hello");
        assert_eq!(
            starlab_core::accounts::recover_ethereum_address(&prehash, &signature).unwrap(),
            account1
        );

        // Device 1 exports its share; a fresh install (same device id, empty
        // keystore) imports it and lists the wallet.
        let (exporter, _, _, exporter_password) = &devices[0];
        let share =
            std::env::temp_dir().join(format!("starlab-share-{}.json", uuid::Uuid::new_v4()));
        let share_path = share.to_string_lossy().into_owned();
        exporter
            .export_share_file(
                &wallet_id,
                "secp256k1",
                share_path.clone(),
                exporter_password.clone(),
            )
            .await
            .expect("export");
        let restored_keystore =
            std::env::temp_dir().join(format!("starlab-e2e-{}", uuid::Uuid::new_v4()));
        let (tx, mut restored_rx) = tokio::sync::mpsc::unbounded_channel();
        let restored = CoreAdapter::new(
            tx,
            "device-1".to_string(),
            restored_keystore.to_string_lossy().into_owned(),
            url.clone(),
            "secp256k1".to_string(),
        );
        restored
            .import_share_file(share_path, exporter_password.clone())
            .await
            .expect("import");
        next_match(&mut restored_rx, "imported wallet", |e| match e {
            UiEvent::Wallets(wallets) => wallets.iter().any(|w| w.id == wallet_id).then_some(()),
            _ => None,
        })
        .await;
        let _ = std::fs::remove_file(share);
        let _ = std::fs::remove_dir_all(restored_keystore);

        let _ = std::fs::remove_dir_all(signer_keystore);
        for (_, _, keystore, _) in devices {
            let _ = std::fs::remove_dir_all(keystore);
        }
    }

    fn session(session_type: SessionType, message: Option<&str>) -> SignalSession {
        SignalSession {
            session_id: "s1".to_string(),
            proposer_id: "peer".to_string(),
            total: 3,
            threshold: 2,
            participants: vec!["peer".to_string()],
            session_type,
            curve_type: "secp256k1".to_string(),
            coordination_type: "online".to_string(),
            signing_message_hex: message.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn path_override_skips_the_dialog() {
        let path = pick_path(Some("/tmp/share.json".into()), IMPORT_PATH_ENV, || {
            panic!("dialog must not open when the override is set")
        })
        .await
        .unwrap();
        assert_eq!(path.as_deref(), Some("/tmp/share.json"));
    }

    #[tokio::test]
    async fn cancelled_dialog_is_not_an_error() {
        let path = pick_path(None, IMPORT_PATH_ENV, || None).await.unwrap();
        assert_eq!(path, None);
    }

    #[tokio::test]
    async fn failing_dialog_names_the_override() {
        let err = pick_path(None, EXPORT_PATH_ENV, || panic!("no portal"))
            .await
            .unwrap_err();
        assert!(err.contains(EXPORT_PATH_ENV), "{err}");
    }

    #[test]
    fn only_open_data_channels_count_as_connected_peers() {
        let mut model = Model::new("me".into());
        let status = &mut model.network_state.participant_webrtc_status;
        status.insert("a".into(), (true, true));
        status.insert("b".into(), (true, false));
        status.insert("gone".into(), (false, false));
        assert_eq!(connected_peers(&model), 1);
    }

    #[test]
    fn only_new_wallet_sessions_are_invites() {
        assert!(invite(&session(SessionType::DKG, None)).is_some());
        let signing = session(
            SessionType::Signing {
                wallet_name: "w-ethereum-0".to_string(),
                curve_type: "secp256k1".to_string(),
                blockchain: "ethereum".to_string(),
                group_public_key: String::new(),
            },
            Some("abcd"),
        );
        assert!(invite(&signing).is_none());
    }

    /// A real adapter (unreachable signal server) for device `me` whose
    /// keystore holds wallet `w1`, plus its UI channel. Returns once the
    /// runner has loaded the wallet (an announce processed before that
    /// would not be for "a wallet we hold").
    async fn adapter_holding_w1() -> (
        CoreAdapter,
        tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
        std::path::PathBuf,
    ) {
        let keystore = std::env::temp_dir().join(format!("starlab-test-{}", uuid::Uuid::new_v4()));
        let wallet_dir = keystore.join("me").join("secp256k1");
        std::fs::create_dir_all(&wallet_dir).unwrap();
        let wallet_file = serde_json::json!({
            "version": "2.0",
            "encrypted": true,
            "algorithm": "AES-256-GCM-PBKDF2",
            "data": "",
            "metadata": {
                "session_id": "w1",
                "device_id": "me",
                "curve_type": "secp256k1",
                "threshold": 2,
                "total_participants": 3,
                "participant_index": 2,
                "group_public_key": "",
                "created_at": "",
                "last_modified": "",
            },
        });
        std::fs::write(wallet_dir.join("w1.json"), wallet_file.to_string()).unwrap();

        let (ui_tx, mut ui_rx) = tokio::sync::mpsc::unbounded_channel();
        let adapter = CoreAdapter::new(
            ui_tx,
            "me".to_string(),
            keystore.to_string_lossy().into_owned(),
            "ws://127.0.0.1:9".to_string(),
            "secp256k1".to_string(),
        );
        next_match(&mut ui_rx, "the test wallet", |e| match e {
            UiEvent::Wallets(wallets) if !wallets.is_empty() => Some(()),
            _ => None,
        })
        .await;
        (adapter, ui_rx, keystore)
    }

    fn peer_signing_announce(wallet_name: &str) -> Message {
        Message::SessionDiscovered {
            session: SignalSession {
                session_id: "sign-1".to_string(),
                proposer_id: "peer".to_string(),
                total: 3,
                threshold: 2,
                participants: vec!["peer".to_string(), "me".to_string()],
                session_type: SessionType::Signing {
                    wallet_name: wallet_name.to_string(),
                    curve_type: "secp256k1".to_string(),
                    // The account id wins over this field.
                    blockchain: "ethereum".to_string(),
                    group_public_key: String::new(),
                },
                curve_type: "secp256k1".to_string(),
                coordination_type: "network".to_string(),
                signing_message_hex: Some("deadbeef".to_string()),
            },
        }
    }

    async fn next_signing_request(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
    ) -> Option<starlab_client::core::SigningRequest> {
        next_match(rx, "a signing request update", |e| match e {
            UiEvent::SigningRequest(request) => Some(request.clone()),
            _ => None,
        })
        .await
    }

    #[tokio::test]
    async fn peer_signing_session_raises_a_request() {
        let (adapter, mut ui_rx, keystore) = adapter_holding_w1().await;
        adapter
            .runner_tx
            .send(peer_signing_announce("w1-ethereum-0"))
            .unwrap();
        let request = next_signing_request(&mut ui_rx)
            .await
            .expect("a peer's signing session must raise a request");
        assert_eq!(request.session_id.as_deref(), Some("sign-1"));
        assert_eq!(request.message_hex, "deadbeef");
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn rejecting_a_peer_request_closes_it() {
        let (adapter, mut ui_rx, keystore) = adapter_holding_w1().await;
        adapter
            .runner_tx
            .send(peer_signing_announce("w1-ethereum-0"))
            .unwrap();
        let request = next_signing_request(&mut ui_rx).await.unwrap();
        adapter.reject_signing(request.id).await.unwrap();
        assert!(next_signing_request(&mut ui_rx).await.is_none());
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[tokio::test]
    async fn bitcoin_account_request_shows_bitcoin() {
        let (adapter, mut ui_rx, keystore) = adapter_holding_w1().await;
        adapter
            .runner_tx
            .send(peer_signing_announce("w1-bitcoin-0"))
            .unwrap();
        assert_eq!(
            next_signing_request(&mut ui_rx).await.unwrap().chain,
            "bitcoin"
        );
        let _ = std::fs::remove_dir_all(keystore);
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
}
