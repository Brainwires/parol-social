//! # parolnet-app
//!
//! The headless ParolNet client core that native clients (the GPUI desktop today, mobile
//! shells later) build on: commands in, observable state out, no UI types.
//!
//! M1 first slice:
//! - **Identity**: an Ed25519 key in the data directory (`PeerId = SHA-256(pubkey)`).
//! - **Pairing**: the PWA's QR / code bootstrap (PNP-003 + PNP-001 §5.3.1). The presenter
//!   shows [`AppHandle::create_pairing_code`]; the scanner calls
//!   [`AppHandle::pair_with_code`], which establishes the Double Ratchet session and sends
//!   the bootstrap envelope over the first data channel.
//! - **Signaling**: the relay's signaling-only profile (register by challenge, `watch` /
//!   `presence`, non-trickle `rtc_offer` / `rtc_answer`, `rtc_ice` for late candidates).
//! - **Transport**: one direct WebRTC connection per contact through `parolnet-rtc`, with
//!   the `parolnet` data channel and the PWA's JSON frames on it. ICE is host + STUN (from
//!   the relay's `/turn-credentials`); TURN is user-supplied only.
//! - **Chat**: 1:1 text as PNP-001 TEXT envelopes, interoperable with the PWA; a sender-side
//!   queue holds envelopes until the contact's data channel opens.
//!
//! The core runs as one tokio task (an actor): [`start`] returns an [`AppHandle`] for
//! commands and a channel of [`AppEvent`]s.

mod engine;
pub mod ice;
mod signaling;
pub mod store;
pub mod wire;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

pub use ice::IceServer;

/// Errors surfaced to the client.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("storage: {0}")]
    Store(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid pairing code: {0}")]
    InvalidCode(String),
    #[error("that is your own code")]
    OwnCode,
    #[error("no secure session with {0}")]
    NoSession(String),
    #[error("unknown contact {0}")]
    UnknownContact(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("configuration: {0}")]
    Config(String),
    #[error("the app core has stopped")]
    Stopped,
}

/// How the app starts.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Where the identity key and state live.
    pub data_dir: PathBuf,
    /// The home relay's WebSocket URL, e.g. `wss://parol.social/ws`.
    pub relay_url: String,
    /// STUN servers. `None` fetches them from the relay's `/turn-credentials`; `Some(vec![])`
    /// uses host candidates only (tests, one network).
    pub stun_servers: Option<Vec<String>>,
    /// The user's own ICE servers ("Relay through my own TURN server"). Passed to the engine;
    /// TURN candidate gathering in `parolnet-rtc` is still to come, so a TURN entry does not
    /// yet create relay candidates.
    pub user_ice_servers: Vec<IceServer>,
    /// The interface address for host candidates. `None` picks the default-route interface
    /// (loopback when there is none).
    pub bind_ip: Option<IpAddr>,
    /// How long a contact's code stays acceptable after it is shown (and offers from
    /// strangers are accepted).
    pub pairing_window: Duration,
    /// Optional name to give contacts by default (`None`: the first 8 hex digits).
    pub default_contact_name: Option<String>,
}

impl AppConfig {
    pub fn new(data_dir: impl Into<PathBuf>, relay_url: impl Into<String>) -> AppConfig {
        AppConfig {
            data_dir: data_dir.into(),
            relay_url: relay_url.into(),
            stun_servers: None,
            user_ice_servers: Vec::new(),
            bind_ip: None,
            pairing_window: Duration::from_secs(30 * 60),
            default_contact_name: None,
        }
    }
}

/// A paired contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub peer_id: String,
    pub name: String,
    /// The contact's Ed25519 identity key (hex) at pairing time: the trust anchor for
    /// identity rotation and safety numbers.
    pub identity_key: Option<String>,
    pub added_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Waiting on this device for the contact's data channel.
    Queued,
    /// Handed to the contact's data channel.
    Sent,
    /// A message we received.
    Received,
    /// Dropped from the queue (limits) before it could be sent.
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: u64,
    pub peer_id: String,
    pub direction: Direction,
    pub text: String,
    pub timestamp_ms: u64,
    pub state: DeliveryState,
}

/// The direct path to a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathState {
    /// No presence information yet.
    Unknown,
    /// The relay says the contact is offline (or does not watch us back yet).
    Offline,
    /// Setting up the WebRTC connection.
    Connecting,
    /// The data channel is open.
    Direct,
    /// The contact is online but no direct path could be built: either side can add a TURN
    /// server of their own.
    NoDirectPath,
}

/// The home relay connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayState {
    Connecting,
    /// Registered; `profile` is `signaling-only` or `relay`.
    Registered {
        profile: String,
    },
    Disconnected {
        reason: String,
    },
}

/// What the core reports to the UI.
#[derive(Debug, Clone, PartialEq)]
pub enum AppEvent {
    Relay(RelayState),
    ContactAdded(Contact),
    ContactUpdated(Contact),
    Path {
        peer_id: String,
        state: PathState,
    },
    Message(ChatMessage),
    MessageState {
        peer_id: String,
        id: u64,
        state: DeliveryState,
    },
    /// Something the user should know (a failed pairing, an unsupported message).
    Notice(String),
}

/// A contact with its live state.
#[derive(Debug, Clone, PartialEq)]
pub struct ContactView {
    pub contact: Contact,
    pub path: PathState,
    pub queued: usize,
}

/// A consistent picture of the core's state.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub peer_id: String,
    pub relay: RelayState,
    pub contacts: Vec<ContactView>,
    pub pairing_open: bool,
}

pub(crate) enum Command {
    CreatePairingCode(oneshot::Sender<Result<String, AppError>>),
    PairWithCode(String, oneshot::Sender<Result<Contact, AppError>>),
    SendText(
        String,
        String,
        oneshot::Sender<Result<ChatMessage, AppError>>,
    ),
    Messages(String, oneshot::Sender<Vec<ChatMessage>>),
    Snapshot(oneshot::Sender<Snapshot>),
    RenameContact(String, String, oneshot::Sender<Result<Contact, AppError>>),
    Connect(String),
    Shutdown(oneshot::Sender<()>),
}

/// The client's end of the core. Cheap to clone.
#[derive(Clone)]
pub struct AppHandle {
    tx: mpsc::UnboundedSender<engine::Input>,
    peer_id: String,
    public_key: String,
}

impl AppHandle {
    /// Our PeerId (hex).
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Our Ed25519 identity public key (hex).
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    async fn ask<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, AppError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(engine::Input::Command(make(tx)))
            .map_err(|_| AppError::Stopped)?;
        rx.await.map_err(|_| AppError::Stopped)
    }

    /// Show this to a contact (as a QR code or text). It stays valid for the pairing window;
    /// a new call replaces the previous code.
    pub async fn create_pairing_code(&self) -> Result<String, AppError> {
        self.ask(Command::CreatePairingCode).await?
    }

    /// Pair with a contact's code (the PWA's QR payload, hex). Establishes the session,
    /// queues the bootstrap envelope and starts connecting.
    pub async fn pair_with_code(&self, code: &str) -> Result<Contact, AppError> {
        let code = code.to_owned();
        self.ask(|tx| Command::PairWithCode(code, tx)).await?
    }

    /// Send a text message: at once over an open data channel, else queued on this device.
    pub async fn send_text(&self, peer_id: &str, text: &str) -> Result<ChatMessage, AppError> {
        let (p, t) = (peer_id.to_owned(), text.to_owned());
        self.ask(|tx| Command::SendText(p, t, tx)).await?
    }

    pub async fn messages(&self, peer_id: &str) -> Result<Vec<ChatMessage>, AppError> {
        let p = peer_id.to_owned();
        self.ask(|tx| Command::Messages(p, tx)).await
    }

    pub async fn snapshot(&self) -> Result<Snapshot, AppError> {
        self.ask(Command::Snapshot).await
    }

    pub async fn rename_contact(&self, peer_id: &str, name: &str) -> Result<Contact, AppError> {
        let (p, n) = (peer_id.to_owned(), name.to_owned());
        self.ask(|tx| Command::RenameContact(p, n, tx)).await?
    }

    /// The user opened a chat or pressed retry: try to connect now.
    pub fn connect(&self, peer_id: &str) {
        let _ = self
            .tx
            .send(engine::Input::Command(Command::Connect(peer_id.to_owned())));
    }

    /// Close every connection, save state and stop the core.
    pub async fn shutdown(&self) {
        let _ = self.ask(Command::Shutdown).await;
    }
}

/// Start the core: load or create the identity, open the store, connect to the relay.
pub async fn start(
    config: AppConfig,
) -> Result<(AppHandle, mpsc::UnboundedReceiver<AppEvent>), AppError> {
    engine::start(config).await
}

/// Install rustls' ring provider once (the workspace builds rustls without a default one).
pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Short display form of a peer id.
pub fn short_id(peer_id: &str) -> String {
    peer_id.chars().take(8).collect()
}

/// Group contacts' path states (for UIs that only want the map).
pub fn paths(snapshot: &Snapshot) -> HashMap<String, PathState> {
    snapshot
        .contacts
        .iter()
        .map(|c| (c.contact.peer_id.clone(), c.path))
        .collect()
}
