//! # parolnet-app
//!
//! The headless ParolNet client core that native clients (the GPUI desktop today, mobile
//! shells later) build on: commands in, observable state out, no UI types.
//!
//! M1:
//! - **Identity**: an Ed25519 key (`PeerId = SHA-256(pubkey)`).
//! - **Storage** ([`store`]): the identity, contacts, sessions, history and queue live in an
//!   encrypted database in the data directory (`parolnet-store`: SQLite with SQLCipher); its
//!   key is kept where [`AppConfig::key_storage`] says. [`delete_all_data`] removes both.
//! - **Pairing**: the QR / code bootstrap (PNP-003 + PNP-001 §5.3.1). The presenter shows
//!   [`AppHandle::create_pairing_code`] (the base45 text of a QR code); the scanner calls
//!   [`AppHandle::pair_with_code`], which derives the Bootstrap Secret and sends its
//!   BootstrapHandshake as the bootstrap envelope over the first data channel. Both prove
//!   knowledge of the secret, exchange pre-key bundles, compare a Short Authentication String
//!   when either asked for it ([`AppConfig::request_sas`], [`AppEvent::SasVerification`],
//!   [`AppHandle::confirm_sas`]) and run the PNP-002 handshake, whose session replaces the
//!   bootstrap one ([`AppEvent::PairingComplete`]). A pairing that fails removes the contact
//!   it added ([`AppEvent::PairingFailed`], [`AppEvent::ContactRemoved`]).
//! - **Signaling**: the relay's signaling-only profile (register by challenge, `watch` /
//!   `presence`, non-trickle `rtc_offer` / `rtc_answer`, `rtc_ice` for late candidates).
//! - **Transport**: one direct WebRTC connection per contact through `parolnet-rtc`, with
//!   the `parolnet` data channel and the PWA's JSON frames on it. ICE is host candidates on
//!   every interface, IPv4 and IPv6, and STUN (from the relay's `/turn-credentials`). When
//!   the machine's network changes ([`AppHandle::network_changed`], called by the core's own
//!   interface watch) connections restart ICE in place where the contact's app can, and are
//!   rebuilt where it cannot or the restart fails. TURN is never taken from a relay: only the server the
//!   user configured ([`TurnSettings`], [`AppHandle::set_turn_settings`]) is used, as one
//!   more candidate or, with `relay_only`, as the only path (the contact then sees that
//!   server's address instead of ours).
//! - **Channel binding** (PNP-001 §10.5.1): both DTLS fingerprints are bound into the session
//!   by a CHANNEL_BINDING envelope on the channel; content and call signals wait for it.
//! - **Chat**: 1:1 text as PNP-001 TEXT envelopes, interoperable with the PWA; a sender-side
//!   queue holds envelopes until the contact's data channel opens and verifies.
//! - **Calls** ([`call`]): 1:1 voice / video on their own connection, signalled inside the
//!   session; the client encodes and decodes (see [`CallMedia`]). A call follows a network
//!   change by ICE restart, gains or loses video by renegotiation
//!   ([`AppHandle::set_call_video`]), tells the encoder what the path carries
//!   ([`MediaEvent::TargetBitrate`]) and reports its quality ([`AppEvent::CallQuality`]).
//!
//! The core runs as one tokio task (an actor): [`start`] returns an [`AppHandle`] for
//! commands and a channel of [`AppEvent`]s.

pub mod call;
mod engine;
pub mod ice;
pub mod qr;
pub mod reconnect;
mod signaling;
pub mod store;
pub mod wire;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

pub use call::{
    CallEnd, CallInfo, CallMedia, CallQuality, CallState, FrameSink, MediaEvent, VideoChange,
    Weakness, video_bitrate_for,
};
/// A pairing code in the form to show for copying as text (the QR code shows the code
/// itself): [`AppHandle::pair_with_code`] takes both.
pub use parolnet_core::bootstrap::qr_text_for_copying as pairing_code_text;
pub use parolnet_rtc::{CandidateKind, ConnectionQuality, MediaKind};
pub use reconnect::ReconnectConfig;
pub use store::KeyStorage;

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
    #[error("no verified direct connection to {0} yet")]
    NotConnected(String),
    #[error("already in a call")]
    Busy,
    #[error("unknown call {0}")]
    UnknownCall(String),
    #[error("the contact's app cannot change a call that is under way")]
    CannotRenegotiate,
    #[error("no pairing with {0} is waiting for a SAS confirmation")]
    NoPairing(String),
    #[error("the app core has stopped")]
    Stopped,
}

/// How the app starts.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Where the encrypted store (identity key and state) lives.
    pub data_dir: PathBuf,
    /// Where the store's key is kept. [`AppConfig::new`] picks [`KeyStorage::File`] (headless
    /// peers, tests); a desktop app sets `KeyStorage::Keychain` (cargo feature `keychain`).
    /// A store keeps the kind it was created with: starting with another is an error.
    pub key_storage: KeyStorage,
    /// The home relay's WebSocket URL, e.g. `wss://parol.social/ws`.
    pub relay_url: String,
    /// STUN servers. `None` fetches them from the relay's `/turn-credentials`; `Some(vec![])`
    /// uses host candidates only (tests, one network).
    pub stun_servers: Option<Vec<String>>,
    /// The one interface address to use for host candidates (tests, a pinned interface).
    /// `None`: every usable address of every interface, IPv4 and IPv6, and the core watches
    /// the interfaces and restarts ICE when they change.
    pub bind_ip: Option<IpAddr>,
    /// How long a pairing code is shown and accepted (and offers from strangers are
    /// accepted): 10 minutes unless changed (PNP-003-SHOULD-001, -SHOULD-003). At most 30
    /// minutes: a scanner refuses older codes (PNP-003-MUST-011).
    pub pairing_window: Duration,
    /// Optional name to give contacts by default (`None`: the first 8 hex digits).
    pub default_contact_name: Option<String>,
    /// How contacts the relay called offline are re-probed.
    pub reconnect: ReconnectConfig,
    /// Ask for SAS verification in every pairing (PNP-003 §5.5): both peers then show a
    /// 6-digit code (and five emoji) that the users compare, and the contact is established
    /// only once both confirmed it. On unless turned off (PNP-003-SHOULD-004, -SHOULD-006):
    /// a peer without a user to compare codes (a bot, a test) turns it off, and still
    /// verifies the SAS when the contact's side asks for it.
    pub request_sas: bool,
    /// Relays to name in pairing codes, one per code in turn (PNP-003-SHOULD-008), as
    /// `hostname:port`. Empty: codes carry no relay hint.
    pub relay_hints: Vec<String>,
    /// Take part in ICE restarts and call renegotiation (PNP-011 sections 7 and 8): list the
    /// features, send and answer `reoffer`s and restart offers. Off, this peer behaves as
    /// one that knows neither (the PWA, the web app today): a network change waits for the
    /// connection to fail and rebuilds it, and a call stays as it was set up.
    pub renegotiation: bool,
}

impl AppConfig {
    pub fn new(data_dir: impl Into<PathBuf>, relay_url: impl Into<String>) -> AppConfig {
        AppConfig {
            data_dir: data_dir.into(),
            key_storage: KeyStorage::File,
            relay_url: relay_url.into(),
            stun_servers: None,
            bind_ip: None,
            pairing_window: Duration::from_secs(10 * 60),
            default_contact_name: None,
            reconnect: ReconnectConfig::default(),
            request_sas: true,
            relay_hints: Vec::new(),
            renegotiation: true,
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
    /// The contact is online but no path could be built: either side can add a TURN server
    /// of their own. Also the state when relay-only is on and the user's TURN server gives
    /// no relay candidate (unreachable, wrong credential): no direct attempt is made then.
    NoDirectPath,
    /// The last direct connection failed its end-to-end check (the DTLS fingerprints the
    /// contact saw differ from ours, PNP-001 §10.5.1): something on the signaling path may
    /// be interfering. Retried with backoff.
    BindingFailed,
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
    /// The pairing code is no longer waiting for a contact (one bootstrapped with it, it
    /// expired or it was cancelled): take it and its QR code off the display.
    PairingCodeClosed,
    /// A contact was removed: the pairing that added it failed (PNP-003 §4, NO_CONTACT).
    ContactRemoved {
        peer_id: String,
    },
    /// A pairing reached SAS_PENDING (PNP-003 §5.5): show the user this Short Authentication
    /// String, as digits and as emoji, and ask them to compare it with what the contact's
    /// device shows, by voice or in person. Then [`AppHandle::confirm_sas`] or
    /// [`AppHandle::reject_sas`]. The pairing is dropped after 10 minutes without both
    /// confirmations.
    SasVerification {
        peer_id: String,
        /// The 6-digit SAS.
        digits: String,
        /// The same value as five emoji.
        emoji: String,
    },
    /// The pairing is complete: the PNP-002 session is established and the bootstrap secret
    /// is erased. `sas_verified`: both users confirmed the SAS.
    PairingComplete {
        peer_id: String,
        sas_verified: bool,
    },
    /// The pairing was aborted (a proof or SAS that did not verify, a rejection, a timeout,
    /// a lost connection): nothing of it is kept.
    PairingFailed {
        peer_id: String,
        reason: String,
    },
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
    /// A call started, changed state or ended, or its video changed.
    Call(CallInfo),
    /// The quality of an active call's connection, about once a second.
    CallQuality {
        call_id: String,
        quality: CallQuality,
    },
}

/// A contact with its live state.
#[derive(Debug, Clone, PartialEq)]
pub struct ContactView {
    pub contact: Contact,
    pub path: PathState,
    pub queued: usize,
    /// ICE restarts completed on the contact's current connection (a diagnostic: the
    /// connection followed that many network changes without being rebuilt).
    pub ice_restarts: u32,
}

/// A consistent picture of the core's state.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub peer_id: String,
    pub relay: RelayState,
    pub contacts: Vec<ContactView>,
    pub pairing_open: bool,
    /// The pairing code to display, while one is waiting for a contact: `None` as soon as a
    /// contact bootstrapped with it, it expired or it was cancelled (PNP-003-MUST-009,
    /// -MUST-048).
    pub pairing_code: Option<String>,
    /// When that code stops being shown (Unix milliseconds), for the expiry indicator
    /// (PNP-003-SHOULD-001).
    pub pairing_expires_ms: Option<u64>,
    /// The user configured their own TURN server (its credential is never in a snapshot).
    pub turn_configured: bool,
    /// Connections use that TURN server only.
    pub relay_only: bool,
}

/// The user's own TURN server ("Relay through my own TURN server"). The only TURN server
/// the app ever uses: none is built in and none is taken from a relay.
///
/// The password is wiped when the value is dropped and never shown by `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnSettings {
    /// `turn:host[:port]` (UDP; `?transport=udp` is accepted, TCP and `turns:` are not yet).
    pub uri: String,
    /// The long-term credential.
    pub username: String,
    pub password: String,
    /// Use the TURN server for every connection and nothing else: contacts see its address
    /// instead of this device's. Off: the relay candidate is one more option next to the
    /// direct ones, for pairs with no direct path.
    #[serde(default)]
    pub relay_only: bool,
}

impl TurnSettings {
    /// Trimmed and checked: a usable `turn:` URI, a username and a password.
    pub fn validated(mut self) -> Result<TurnSettings, AppError> {
        self.uri = self.uri.trim().to_owned();
        self.username = self.username.trim().to_owned();
        parolnet_rtc::parse_turn_uri(&self.uri).map_err(|e| AppError::Config(e.to_string()))?;
        if self.username.is_empty() {
            return Err(AppError::Config("the TURN server needs a username".into()));
        }
        if self.password.is_empty() {
            return Err(AppError::Config("the TURN server needs a password".into()));
        }
        Ok(self)
    }
}

impl std::fmt::Debug for TurnSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnSettings")
            .field("uri", &self.uri)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("relay_only", &self.relay_only)
            .finish()
    }
}

impl Drop for TurnSettings {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}

pub(crate) enum Command {
    CreatePairingCode(oneshot::Sender<Result<String, AppError>>),
    PairWithCode(String, oneshot::Sender<Result<Contact, AppError>>),
    CancelPairingCode,
    ConfirmSas(String, oneshot::Sender<Result<(), AppError>>),
    RejectSas(String),
    SendText(
        String,
        String,
        oneshot::Sender<Result<ChatMessage, AppError>>,
    ),
    Messages(String, oneshot::Sender<Vec<ChatMessage>>),
    Snapshot(oneshot::Sender<Snapshot>),
    RenameContact(String, String, oneshot::Sender<Result<Contact, AppError>>),
    Connect(String),
    StartCall(String, bool, oneshot::Sender<Result<CallInfo, AppError>>),
    AcceptCall(String, oneshot::Sender<Result<CallInfo, AppError>>),
    RejectCall(String),
    Hangup(String),
    TakeCallMedia(String, oneshot::Sender<Result<CallMedia, AppError>>),
    SetCallVideo(String, bool, oneshot::Sender<Result<VideoChange, AppError>>),
    NetworkChanged,
    TurnSettings(oneshot::Sender<Option<TurnSettings>>),
    SetTurnSettings(Option<TurnSettings>, oneshot::Sender<Result<(), AppError>>),
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

    /// The safety number to compare with `peer_id` out of band (PNP-002 §10).
    pub fn safety_number(&self, peer_id: &str) -> Option<String> {
        safety_number(&self.peer_id, peer_id)
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

    /// Show this to a contact (as a QR code, error correction level M or higher, or as
    /// text). It stays valid for the pairing window and for one pairing; a new call replaces
    /// the previous code.
    pub async fn create_pairing_code(&self) -> Result<String, AppError> {
        self.ask(Command::CreatePairingCode).await?
    }

    /// Pair with a contact's code (the text of their QR code: base45 of the PNP-003 QR
    /// payload). Derives the Bootstrap Secret and starts connecting; the BootstrapHandshake
    /// goes out when the data channel opens. The contact is listed at once, and removed
    /// again if the pairing fails ([`AppEvent::PairingFailed`]).
    pub async fn pair_with_code(&self, code: &str) -> Result<Contact, AppError> {
        let code = code.to_owned();
        self.ask(|tx| Command::PairWithCode(code, tx)).await?
    }

    /// Stop waiting for a contact: the current pairing code is forgotten and must come off
    /// the display.
    pub fn cancel_pairing_code(&self) {
        let _ = self
            .tx
            .send(engine::Input::Command(Command::CancelPairingCode));
    }

    /// The user compared the SAS of [`AppEvent::SasVerification`] and it matches: send our
    /// confirmation (PNP-003-MUST-028). The pairing completes once the contact's
    /// confirmation has arrived and verified.
    pub async fn confirm_sas(&self, peer_id: &str) -> Result<(), AppError> {
        let p = peer_id.to_owned();
        self.ask(|tx| Command::ConfirmSas(p, tx)).await?
    }

    /// The SAS does not match (or the user will not compare it): abort the pairing and
    /// erase its state.
    pub fn reject_sas(&self, peer_id: &str) {
        let _ = self.tx.send(engine::Input::Command(Command::RejectSas(
            peer_id.to_owned(),
        )));
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

    /// Call a contact over a verified direct connection: audio, plus video when `video`.
    pub async fn start_call(&self, peer_id: &str, video: bool) -> Result<CallInfo, AppError> {
        let p = peer_id.to_owned();
        self.ask(|tx| Command::StartCall(p, video, tx)).await?
    }

    /// Accept an incoming call (with video when the caller offered it).
    pub async fn accept_call(&self, call_id: &str) -> Result<CallInfo, AppError> {
        let c = call_id.to_owned();
        self.ask(|tx| Command::AcceptCall(c, tx)).await?
    }

    /// Decline an incoming call.
    pub fn reject_call(&self, call_id: &str) {
        let _ = self.tx.send(engine::Input::Command(Command::RejectCall(
            call_id.to_owned(),
        )));
    }

    /// End a call (outgoing, connecting or active).
    pub fn hangup(&self, call_id: &str) {
        let _ = self
            .tx
            .send(engine::Input::Command(Command::Hangup(call_id.to_owned())));
    }

    /// The call's media: where to send our encoded frames and the contact's RTP. Once per
    /// call; take it when the call starts (outgoing) or is accepted.
    pub async fn take_call_media(&self, call_id: &str) -> Result<CallMedia, AppError> {
        let c = call_id.to_owned();
        self.ask(|tx| Command::TakeCallMedia(c, tx)).await?
    }

    /// Turn our video on or off in a call that is set up. With a contact whose app
    /// renegotiates ([`CallInfo::renegotiable`]) the call is renegotiated: an audio call
    /// gains video, and a camera that is turned off stops its stream
    /// ([`VideoChange::Renegotiating`]). With any other contact a video call keeps its
    /// stream ([`VideoChange::Unchanged`]: send black for "off") and an audio call cannot
    /// gain video ([`AppError::CannotRenegotiate`]).
    pub async fn set_call_video(
        &self,
        call_id: &str,
        enabled: bool,
    ) -> Result<VideoChange, AppError> {
        let c = call_id.to_owned();
        self.ask(|tx| Command::SetCallVideo(c, enabled, tx)).await?
    }

    /// The machine's network changed (an interface came or went, another Wi-Fi): reconnect
    /// to the relay now and restart ICE on the connections and the call. The core calls this
    /// itself when it watches the interfaces ([`AppConfig::bind_ip`] is `None`); a client
    /// that learns of a change another way (the system woke up) may call it too.
    pub fn network_changed(&self) {
        let _ = self
            .tx
            .send(engine::Input::Command(Command::NetworkChanged));
    }

    /// The user's TURN server, if they configured one (for the settings view; snapshots
    /// only say whether one is set).
    pub async fn turn_settings(&self) -> Result<Option<TurnSettings>, AppError> {
        self.ask(Command::TurnSettings).await
    }

    /// Use the user's own TURN server from now on, and remember it. Refused when the URI is
    /// not `turn:host[:port]` over UDP or the credential is incomplete. New connections use
    /// it at once and existing data connections are rebuilt, without a restart.
    pub async fn set_turn_settings(&self, settings: TurnSettings) -> Result<(), AppError> {
        self.ask(|tx| Command::SetTurnSettings(Some(settings), tx))
            .await?
    }

    /// Forget the TURN server: connections are direct again.
    pub async fn clear_turn_settings(&self) -> Result<(), AppError> {
        self.ask(|tx| Command::SetTurnSettings(None, tx)).await?
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

/// "Delete all data on this device": remove the encrypted store in `config.data_dir` (the
/// identity, contacts, sessions, history, queue) and its key from `config.key_storage`.
/// Shut the core down first ([`AppHandle::shutdown`]); the next [`start`] makes a new
/// identity.
pub fn delete_all_data(config: &AppConfig) -> Result<(), AppError> {
    store::wipe(&config.data_dir, &config.key_storage)
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

/// The 60-digit safety number of two peer ids (hex), as the PWA shows it (PNP-002 §10).
/// `None` when either is not a 64-character hex id.
pub fn safety_number(a: &str, b: &str) -> Option<String> {
    let a: [u8; 32] = hex::decode(a).ok()?.try_into().ok()?;
    let b: [u8; 32] = hex::decode(b).ok()?.try_into().ok()?;
    Some(parolnet_protocol::channel_binding::safety_number(&a, &b))
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
