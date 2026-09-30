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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::ui_callback::{Invite, NativeUICallback, UiEvent};

/// Shape of every wallet the desktop creates: 2-of-3. The UI states this so
/// users know how many devices to bring.
pub const DEFAULT_TOTAL: u16 = 3;
pub const DEFAULT_THRESHOLD: u16 = 2;

/// Env overrides that skip the native file dialogs (headless / Xvfb runs have
/// no desktop file portal, so the dialog would never open). Import takes a
/// key-share file or a folder of them; export takes a folder.
const IMPORT_PATH_ENV: &str = "MPC_IMPORT_PATH";
const EXPORT_PATH_ENV: &str = "MPC_EXPORT_PATH";

/// A dialog that has not answered by then is treated as unable to open.
const DIALOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

fn env_path(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|p| !p.trim().is_empty())
}

/// The paths to use: `override_path` when set (from `env_var`), else the
/// native `dialog`'s answer. No paths means the user cancelled; a dialog
/// that fails or never opens is an error naming the override.
async fn pick_paths<F>(
    override_path: Option<String>,
    env_var: &str,
    dialog: F,
) -> Result<Vec<PathBuf>, String>
where
    F: FnOnce() -> Vec<PathBuf> + Send + 'static,
{
    if let Some(path) = override_path {
        return Ok(vec![PathBuf::from(path)]);
    }
    match tokio::time::timeout(DIALOG_TIMEOUT, tokio::task::spawn_blocking(dialog)).await {
        Ok(Ok(paths)) => Ok(paths),
        Ok(Err(e)) => Err(format!(
            "The file dialog failed ({e}). Set {env_var} to a path instead."
        )),
        Err(_) => Err(format!(
            "The file dialog did not open (no desktop file portal?). Set {env_var} to a path \
             instead."
        )),
    }
}

/// The key-share files at `path`: the `.json` files of a folder (sorted),
/// else the file itself.
fn share_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let entries =
        std::fs::read_dir(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{} holds no key-share files", path.display()));
    }
    Ok(files)
}

/// Where a wallet's key share on `curve` is exported inside `dir`.
fn export_file(dir: &Path, wallet_id: &str, curve: &str) -> PathBuf {
    dir.join(format!("{wallet_id}-{curve}.json"))
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

/// Spawn the secp256k1 runner (FROST BIP-340 + threshold ECDSA) with
/// `primes` as its source of ECDSA safe primes. The runner starts
/// generating them as soon as it runs.
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

/// The FROST part of the open wallet ceremony is done and the wallet's
/// threshold-ECDSA key ceremony runs: the engine marks FROST `Complete`
/// but keeps the ceremony open until the ECDSA share is persisted
/// (`DKGFinalized`).
fn ecdsa_key_phase(model: &Model) -> bool {
    ceremony_open(model)
        && !model.wallet_state.dkg_in_progress
        && matches!(
            model.wallet_state.dkg_round,
            starlab_client::elm::message::DKGRound::Complete
        )
}

/// The engine's notice that the ECDSA DKG worker waits for safe primes.
fn is_primes_wait_notice(msg: &Message) -> bool {
    matches!(msg, Message::ShowNotification { text, .. } if text.contains("safe primes"))
}

/// This device's ECDSA setup: the Paillier safe primes a wallet's
/// threshold-ECDSA key ceremony needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaSetup {
    /// A set of primes is ready for the next wallet.
    Ready,
    /// The background generator has been working for this long.
    Preparing(Duration),
}

/// Tracks how long the current prime generation has been running, from
/// `PrimeSupply::is_ready` samples: a DKG takes the ready set and the
/// generator starts on the next one, so a ready → not-ready edge restarts
/// the clock.
#[derive(Debug)]
struct PrimesClock {
    since: Instant,
    was_ready: bool,
}

impl PrimesClock {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            was_ready: false,
        }
    }

    fn sample(&mut self, ready: bool, now: Instant) -> EcdsaSetup {
        if ready {
            self.was_ready = true;
            return EcdsaSetup::Ready;
        }
        if self.was_ready {
            self.was_ready = false;
            self.since = now;
        }
        EcdsaSetup::Preparing(now.saturating_duration_since(self.since))
    }
}

/// The runner's prime supply plus the clock behind [`EcdsaSetup::Preparing`].
struct PrimesWatch {
    supply: PrimeSupply,
    clock: std::sync::Mutex<PrimesClock>,
}

impl PrimesWatch {
    fn status(&self) -> EcdsaSetup {
        let ready = self.supply.is_ready();
        self.clock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sample(ready, Instant::now())
    }
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
    /// ECDSA safe primes (secp256k1 runner only; ed25519 wallets have no
    /// ECDSA key).
    primes: Option<PrimesWatch>,
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

    /// [`Self::new`] with an explicit source of ECDSA safe primes (tests
    /// inject fixed ones to skip minutes of generation).
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

        // Only the secp256k1 runner creates an ECDSA key.
        let has_ecdsa = curve != "ed25519";

        // on_sync: mirror the runner's model into the UI after every message.
        let on_sync = move |model: &Model, msg: Option<&Message>| {
            let ecdsa_key = has_ecdsa && ecdsa_key_phase(model);
            if ecdsa_key && msg.is_some_and(is_primes_wait_notice) {
                let _ = ui_tx.send(UiEvent::EcdsaWaitingForPrimes);
            }
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
            let active = model.wallet_state.dkg_in_progress && !dkg_done;
            let (round, progress) = if active {
                dkg_round_progress(&model.wallet_state.dkg_round)
            } else {
                (0, 0.0)
            };
            let events = [
                UiEvent::Connected(model.network_state.connected),
                UiEvent::Peers(connected_peers(model)),
                UiEvent::Wallets(crate::wallet_view::group_wallets(
                    &model.wallet_state.wallets,
                )),
                UiEvent::Invites(model.session_invites.iter().filter_map(invite).collect()),
                UiEvent::ActiveSession(model.active_session.as_ref().and_then(invite)),
                UiEvent::CeremonyOpen(ceremony_open(model)),
                UiEvent::DkgStatus {
                    active,
                    round,
                    progress,
                    ecdsa_key,
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
        let (runner_tx, runner_control, primes) = if curve == "ed25519" {
            let (tx, control) = spawn_ed25519_runner(device_id, keystore_path, signal_url, on_sync);
            (tx, control, None)
        } else {
            // "unified" and "secp256k1" both run on the secp256k1 runner.
            // Its `run` starts the prime generator; starting it here too
            // (idempotent) makes the setup clock start with the app.
            primes.start();
            let watch = PrimesWatch {
                supply: primes.clone(),
                clock: std::sync::Mutex::new(PrimesClock::new(Instant::now())),
            };
            let (tx, control) =
                spawn_secp256k1_runner(device_id, keystore_path, signal_url, primes, on_sync);
            (tx, control, Some(watch))
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
            primes,
        }
    }

    /// This device's ECDSA setup, or `None` when this runner creates no
    /// ECDSA keys (ed25519).
    pub fn ecdsa_setup(&self) -> Option<EcdsaSetup> {
        self.primes.as_ref().map(PrimesWatch::status)
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
    /// device's keystore — a wallet has one file per key (Ethereum ECDSA,
    /// Bitcoin Taproot, Solana); the runner then re-reads the keystore so
    /// the wallet shows up. The files come from `MPC_IMPORT_PATH` (a file or
    /// a folder) when set, else from a native multi-file picker. A cancelled
    /// picker is not an error.
    pub async fn import_share(&self, password: String) -> Result<(), String> {
        let picked = pick_paths(env_path(IMPORT_PATH_ENV), IMPORT_PATH_ENV, || {
            rfd::FileDialog::new()
                .add_filter("Starlab key share", &["json"])
                .set_title("Import a wallet's key-share files")
                .pick_files()
                .unwrap_or_default()
        })
        .await?;
        let mut files = Vec::new();
        for path in &picked {
            files.extend(share_files(path)?);
        }
        self.import_share_files(&files, password).await
    }

    async fn import_share_files(&self, files: &[PathBuf], password: String) -> Result<(), String> {
        for file in files {
            self.wallet_manager
                .import_wallet(file.to_string_lossy().into_owned(), password.clone())
                .await
                .map_err(|e| format!("{}: {e}", file.display()))?;
        }
        let _ = self.runner_tx.send(Message::ListWallets);
        Ok(())
    }

    /// Export this device's key shares of `wallet_id` — one file per key in
    /// `curves`, `<wallet_id>-<curve>.json`, still encrypted with the wallet
    /// `password` — into a folder: `MPC_EXPORT_PATH` when set, else one
    /// picked in a native dialog.
    pub async fn export_share(
        &self,
        wallet_id: String,
        curves: Vec<String>,
        password: String,
    ) -> Result<(), String> {
        let picked = pick_paths(env_path(EXPORT_PATH_ENV), EXPORT_PATH_ENV, || {
            rfd::FileDialog::new()
                .set_title("Export the wallet's key shares to a folder")
                .pick_folder()
                .into_iter()
                .collect()
        })
        .await?;
        let Some(dir) = picked.first() else {
            return Ok(());
        };
        self.export_share_files(&wallet_id, &curves, dir, password)
            .await
    }

    async fn export_share_files(
        &self,
        wallet_id: &str,
        curves: &[String],
        dir: &Path,
        password: String,
    ) -> Result<(), String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        for curve in curves {
            let path = export_file(dir, wallet_id, curve);
            self.wallet_manager
                .export_wallet(
                    wallet_id,
                    curve,
                    path.to_string_lossy().into_owned(),
                    password.clone(),
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
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
    use starlab_core::accounts::ECDSA_CURVE;
    use tokio::sync::watch;

    /// **INSECURE** fixed safe primes (the engine's test fixture) so a test
    /// DKG doesn't spend minutes generating them. Never for real wallets.
    fn insecure_test_primes() -> PrimeSupply {
        let sets: Vec<starlab_core::ecdsa::Primes> =
            serde_json::from_str(include_str!("../testdata/insecure-test-primes.json"))
                .expect("primes fixture");
        PrimeSupply::insecure_test_fixed(sets.into_iter().next().expect("one set"))
    }

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
            PrimeSupply::background(),
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
    /// 2-of-3 wallet (FROST + threshold ECDSA), sign with its Ethereum
    /// account 1 from one device while another approves the request (the
    /// Sign tab and Signature request card paths) and check the signature
    /// ecrecovers to that account, then export the wallet's key shares and
    /// import them into a fresh install.
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
                insecure_test_primes(),
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
        // The wallet is complete once its ECDSA (Ethereum) key is saved: one
        // row with the Ethereum and Bitcoin accounts.
        let mut wallet = None;
        for (_, rx, _, _) in devices.iter_mut() {
            wallet = Some(
                next_match(rx, "finished wallet", |e| match e {
                    UiEvent::Wallets(wallets) => wallets
                        .iter()
                        .find(|w| w.key(ECDSA_CURVE).is_some())
                        .cloned(),
                    _ => None,
                })
                .await,
            );
        }
        let wallet = wallet.unwrap();
        let wallet_id = wallet.id.clone();
        assert_eq!(
            wallet
                .accounts(0)
                .iter()
                .map(|a| a.chain)
                .collect::<Vec<_>>(),
            ["ethereum", "bitcoin"]
        );
        let account_address = wallet.account("ethereum", 1).unwrap().address;

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
        assert_eq!(
            hex::decode(signature.trim_start_matches("0x"))
                .unwrap()
                .len(),
            65,
            "r ‖ s ‖ v"
        );
        assert_eq!(
            crate::check_ethereum_signature(b"Hello", &signature, &account_address),
            Ok(())
        );

        // Device 1 exports its key shares (one file per key); a fresh install
        // (same device id, empty keystore) imports the folder and lists the
        // wallet with both keys.
        let (exporter, _, _, exporter_password) = &devices[0];
        let share_dir =
            std::env::temp_dir().join(format!("starlab-shares-{}", uuid::Uuid::new_v4()));
        let curves: Vec<String> = wallet.curves().map(str::to_string).collect();
        exporter
            .export_share_files(&wallet_id, &curves, &share_dir, exporter_password.clone())
            .await
            .expect("export");
        let restored_keystore =
            std::env::temp_dir().join(format!("starlab-e2e-{}", uuid::Uuid::new_v4()));
        let (tx, mut restored_rx) = tokio::sync::mpsc::unbounded_channel();
        let restored = CoreAdapter::with_primes(
            tx,
            "device-1".to_string(),
            restored_keystore.to_string_lossy().into_owned(),
            url.clone(),
            "secp256k1".to_string(),
            insecure_test_primes(),
        );
        restored
            .import_share_files(&share_files(&share_dir).unwrap(), exporter_password.clone())
            .await
            .expect("import");
        next_match(&mut restored_rx, "imported wallet", |e| match e {
            UiEvent::Wallets(wallets) => wallets
                .iter()
                .any(|w| w.id == wallet_id && w.keys.len() == curves.len())
                .then_some(()),
            _ => None,
        })
        .await;
        let _ = std::fs::remove_dir_all(share_dir);
        let _ = std::fs::remove_dir_all(restored_keystore);

        let _ = std::fs::remove_dir_all(signer_keystore);
        for (_, _, keystore, _) in devices {
            let _ = std::fs::remove_dir_all(keystore);
        }
    }

    #[test]
    fn primes_clock_counts_from_start_until_ready() {
        let t0 = Instant::now();
        let mut clock = PrimesClock::new(t0);
        assert_eq!(
            clock.sample(false, t0 + Duration::from_secs(72)),
            EcdsaSetup::Preparing(Duration::from_secs(72))
        );
        assert_eq!(
            clock.sample(true, t0 + Duration::from_secs(90)),
            EcdsaSetup::Ready
        );
    }

    #[test]
    fn primes_clock_restarts_when_a_dkg_takes_the_ready_set() {
        let t0 = Instant::now();
        let mut clock = PrimesClock::new(t0);
        clock.sample(true, t0 + Duration::from_secs(90));
        // A DKG took the set; the generator works on the next one.
        assert_eq!(
            clock.sample(false, t0 + Duration::from_secs(100)),
            EcdsaSetup::Preparing(Duration::ZERO)
        );
        assert_eq!(
            clock.sample(false, t0 + Duration::from_secs(130)),
            EcdsaSetup::Preparing(Duration::from_secs(30))
        );
    }

    #[tokio::test]
    async fn secp256k1_device_prepares_primes_and_ed25519_has_none() {
        let keystore = std::env::temp_dir().join(format!("starlab-test-{}", uuid::Uuid::new_v4()));
        let path = keystore.to_string_lossy().into_owned();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let secp = CoreAdapter::new(
            tx.clone(),
            "me".into(),
            path.clone(),
            "ws://127.0.0.1:9".into(),
            "secp256k1".into(),
        );
        assert!(matches!(secp.ecdsa_setup(), Some(EcdsaSetup::Preparing(_))));
        let fixed = CoreAdapter::with_primes(
            tx.clone(),
            "me".into(),
            path.clone(),
            "ws://127.0.0.1:9".into(),
            "secp256k1".into(),
            insecure_test_primes(),
        );
        assert_eq!(fixed.ecdsa_setup(), Some(EcdsaSetup::Ready));
        let ed = CoreAdapter::new(
            tx,
            "me".into(),
            path,
            "ws://127.0.0.1:9".into(),
            "ed25519".into(),
        );
        assert_eq!(ed.ecdsa_setup(), None);
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn ecdsa_key_phase_follows_frost_until_the_wallet_is_final() {
        use starlab_client::elm::message::DKGRound;
        let mut model = Model::new("me".into());
        model.wallet_state.creating_wallet = Some(Default::default());
        model.wallet_state.dkg_in_progress = true;
        model.wallet_state.dkg_round = DKGRound::Round2;
        assert!(!ecdsa_key_phase(&model), "FROST still running");
        // FROST done (`DKGKeyGenerated`), ECDSA ceremony before `DKGFinalized`.
        model.wallet_state.dkg_in_progress = false;
        model.wallet_state.dkg_round = DKGRound::Complete;
        assert!(ecdsa_key_phase(&model));
        // `DKGFinalized` closes the ceremony.
        model.wallet_state.creating_wallet = None;
        assert!(!ecdsa_key_phase(&model));
    }

    #[test]
    fn engine_primes_notice_is_recognised() {
        use starlab_client::elm::model::NotificationKind;
        let notice = |text: &str| Message::ShowNotification {
            text: text.to_string(),
            kind: NotificationKind::Info,
        };
        assert!(is_primes_wait_notice(&notice(
            "Generating ECDSA safe primes for the Ethereum key (first run can take a few minutes)…"
        )));
        assert!(!is_primes_wait_notice(&notice("Wallet created")));
    }

    #[test]
    fn a_folder_imports_every_share_file_in_it() {
        let dir = std::env::temp_dir().join(format!("starlab-shares-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for curve in ["secp256k1", ECDSA_CURVE] {
            std::fs::write(export_file(&dir, "w1", curve), "{}").unwrap();
        }
        std::fs::write(dir.join("notes.txt"), "").unwrap();
        let files = share_files(&dir).unwrap();
        assert_eq!(
            files,
            [
                export_file(&dir, "w1", ECDSA_CURVE),
                export_file(&dir, "w1", "secp256k1")
            ]
        );
        let single = export_file(&dir, "w1", "secp256k1");
        assert_eq!(share_files(&single).unwrap(), std::slice::from_ref(&single));
        let _ = std::fs::remove_dir_all(dir);
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
        let paths = pick_paths(Some("/tmp/share.json".into()), IMPORT_PATH_ENV, || {
            panic!("dialog must not open when the override is set")
        })
        .await
        .unwrap();
        assert_eq!(paths, [PathBuf::from("/tmp/share.json")]);
    }

    #[tokio::test]
    async fn cancelled_dialog_is_not_an_error() {
        let paths = pick_paths(None, IMPORT_PATH_ENV, Vec::new).await.unwrap();
        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn failing_dialog_names_the_override() {
        let err = pick_paths(None, EXPORT_PATH_ENV, || panic!("no portal"))
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
