//! The core actor: one task owns the identity, sessions, contacts, store and every contact
//! connection. Commands from the client, relay frames from the signaling task, connection
//! events from `parolnet-rtc` tasks and timers all arrive as [`Input`]s.

mod transfers;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parolnet_core::bootstrap::NonceTracker;
use parolnet_core::bootstrap::pairing::PairingState;
use parolnet_core::envelope::{decrypt_for_peer, encrypt_for_peer, try_bootstrap_and_decrypt};
use parolnet_core::{ParolNet, ParolNetConfig};
use parolnet_protocol::PeerId;
use parolnet_protocol::ProtocolCodec as _;
use parolnet_protocol::channel_binding::{BindingError, ChannelBinding};
use parolnet_protocol::codec::CborCodec;
use parolnet_protocol::shaping::{BandwidthMode, SendChoice, SendScheduler};
use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtc::peer_connection::transport::RTCIceCandidateInit;
use parolnet_rtc::rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::{
    Gather, IcePolicy, MediaKind, NetworkMonitor, RtcConfig, RtcError, RtcEvent, RtcHandle,
    SystemNetwork, TurnServer,
};
use rand::Rng as _;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::call::{
    CallEnd, CallInfo, CallMedia, CallQuality, CallSignal, CallState, FrameSink, MediaEvent,
    OfferDecision, OutFrame, ReofferDecision, VideoChange, local_features, new_call_id,
};
use crate::reconnect::ProbeSchedule;
use crate::signaling::{self, SigEvent, SigHandle, Signer};
use crate::store::{QueuedEnvelope, State, Store};
use crate::wire::{
    ClientFrame, DATA_CHANNEL_LABEL, DcFrame, RestartExpiry, RestartOffer, SdpJson, ServerFrame,
    SignalKind, is_peer_id, msg_type, same_dtls_session, should_initiate,
};
use crate::{
    AppConfig, AppError, AppEvent, AppHandle, ChatMessage, Command, Contact, ContactView,
    DeliveryState, Direction, PathState, RelayState, Snapshot, TurnSettings, now_ms,
};

/// The initiator's wait for an answer (as the PWA).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);
/// From starting a connection to an open data channel (STUN gathering, signaling, ICE,
/// DTLS, SCTP).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// The non-initiator waits this long (plus up to 2 s) for the initiator's offer.
const OFFER_FALLBACK: Duration = Duration::from_secs(10);
/// A disconnected ICE connection gets this long to recover.
const DISCONNECT_GRACE: Duration = Duration::from_secs(5);
const RETRY_BASE: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const RETRY_MAX_ATTEMPTS: u32 = 8;
/// New offers: at most 3 per 10 s (the relay allows 60 signaling frames a minute).
const OFFERS_PER_WINDOW: usize = 3;
const OFFER_WINDOW: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_secs(15);
const WATCH_MAX: usize = 256;
const PENDING_ICE_MAX: usize = 32;
/// PNP-001-MUST-081: the peer's channel binding must verify this long after the data channel
/// opens, or the connection is closed.
const BINDING_TIMEOUT: Duration = Duration::from_secs(20);
/// An unanswered call rings this long (as the PWA).
const CALL_RING_TIMEOUT: Duration = crate::call::RING_TIMEOUT;
/// From accepting (or the answer) to media flowing.
const CALL_CONNECT_TIMEOUT: Duration = crate::call::CONNECT_TIMEOUT;
const CALL_PENDING_ICE_MAX: usize = crate::call::MAX_PENDING_CANDIDATES;
/// Media events waiting for the client (RTP beyond this is dropped).
const CALL_MEDIA_CAPACITY: usize = 2048;
const RESTART_TIMEOUT: Duration = crate::wire::RESTART_TIMEOUT;
const CALL_REOFFER_TIMEOUT: Duration = crate::call::REOFFER_TIMEOUT;

pub(crate) enum Input {
    Command(Command),
    Sig(SigEvent),
    Stun(Vec<String>),
    RtcReady {
        peer: String,
        epoch: u64,
        result: Result<RtcHandle, StartFailure>,
    },
    Rtc {
        peer: String,
        epoch: u64,
        event: RtcEvent,
    },
    Timer(Timer),
    /// The contact's end acknowledged a content envelope sent on its data channel.
    ContentAcked {
        peer: String,
        envelope: String,
    },
    Tick,
    /// The machine's usable addresses changed (the interface watch).
    NetworkChanged,
    CallRtcReady {
        call_id: String,
        result: Result<RtcHandle, StartFailure>,
    },
    CallRtc {
        call_id: String,
        event: RtcEvent,
    },
    /// A data channel under `pn-` opened on a contact's connection (PNP-010).
    FileChannel {
        peer: String,
        epoch: u64,
        dc: usize,
        label: String,
        rx: mpsc::Receiver<crate::transfer::ChannelEvent>,
    },
    /// A transfer's worker reports.
    Transfer {
        id: String,
        event: crate::transfer::WorkerEvent,
    },
    /// The file of an `offer_file` command has been read for its hash.
    OfferHashed {
        peer: String,
        result: std::io::Result<crate::transfer::Hashed>,
        reply: tokio::sync::oneshot::Sender<Result<crate::TransferInfo, AppError>>,
    },
}

/// Why a connection could not start.
pub(crate) struct StartFailure {
    message: String,
    /// No relay candidate although the user asked for relay-only.
    no_relay: bool,
}

impl From<RtcError> for StartFailure {
    fn from(e: RtcError) -> Self {
        StartFailure {
            no_relay: matches!(e, RtcError::Turn(_) | RtcError::TurnUri(_)),
            message: e.to_string(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Timer {
    AnswerTimeout {
        peer: String,
        epoch: u64,
    },
    ConnectTimeout {
        peer: String,
        epoch: u64,
    },
    DisconnectGrace {
        peer: String,
        epoch: u64,
    },
    BindingTimeout {
        peer: String,
        epoch: u64,
    },
    RestartTimeout {
        peer: String,
        epoch: u64,
        generation: u64,
    },
    CallReoffer {
        call_id: String,
        generation: u64,
    },
    CallRing {
        call_id: String,
    },
    CallConnect {
        call_id: String,
    },
    OfferFallback {
        peer: String,
    },
    OfferSlot {
        peer: String,
    },
    Retry {
        peer: String,
    },
    /// The next send slot of a contact's data channel is due (PNP-006 §4.1).
    Pace {
        peer: String,
        epoch: u64,
    },
    // A soft-offline contact is due for a probe (see `reconnect`).
    Probe,
    /// Open channels for the transfers we receive from this contact (again).
    TransferPump {
        peer: String,
    },
    /// A transfer channel we asked for should be open by now.
    TransferOpen {
        id: String,
        epoch: u64,
    },
}

#[path = "pairing.rs"]
mod pairing;
use pairing::PairingSlot;

/// The presenter's half of a QR bootstrap (PNP-003), kept while its code is valid and until
/// one peer has bootstrapped with it (PNP-003-MUST-040).
struct PendingBootstrap {
    seed: [u8; 32],
    ratchet_secret: [u8; 32],
    /// The code as shown (the text of the QR code) and when it stops being shown.
    code: String,
    expires_ms: u64,
}

impl Drop for PendingBootstrap {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.ratchet_secret.zeroize();
        self.code.zeroize();
    }
}

/// What waits for a send slot on a data channel ahead of the content queue: the frames that
/// set the channel up, call signals and file-transfer messages (PNP-006-MAY-002).
enum Outgoing {
    /// A frame that exists only for this connection (identity, a pairing's handshake
    /// message, our binding, a call signal).
    Frame(String),
    /// The control message the transfer with this id owes the contact (PNP-010). It is
    /// built in its slot and stays owed in the store until then, so a connection that ends
    /// first loses nothing.
    TransferControl(String),
}

struct Conn {
    epoch: u64,
    handle: Option<RtcHandle>,
    initiator: bool,
    /// An answerer's remote offer, applied once the connection task is up.
    remote_offer: Option<RTCSessionDescription>,
    remote_set: bool,
    pending_ice: Vec<RTCIceCandidateInit>,
    dc: Option<usize>,
    last_state: Option<RTCPeerConnectionState>,
    /// Our local description and the remote one we applied (for the channel binding).
    local_sdp: Option<String>,
    remote_sdp: Option<String>,
    /// Our CHANNEL_BINDING went out on this connection.
    binding_sent: bool,
    /// The peer's CHANNEL_BINDING verified (PNP-001 §10.5.1): only now is the path direct.
    verified: bool,
    /// Our first description (the one the binding covers) went out; later ones belong to an
    /// ICE restart.
    described: bool,
    /// The peer's identity frame listed `ice-restart`: a restart offer is applied to this
    /// connection instead of replacing it.
    peer_restarts: bool,
    /// An ICE restart we asked for.
    restart: Option<Restart>,
    /// A restart's offer or answer made while the relay was away: sent when it is back.
    unsent: Option<(SignalKind, String)>,
    /// ICE restarts completed on this connection (ours and the peer's).
    restarts_done: u32,
    /// The peer's restart offer was applied and the connection has not come back yet.
    peer_restarting: bool,
    /// The channel's send schedule (PNP-006 §4.1 to §4.4): one frame per slot, slots a
    /// padding interval plus jitter apart. Its own queue holds the [`Outgoing`] frames;
    /// content waits in the stored queue. Cover traffic is off: a direct path carries none
    /// (PNP-006-SHOULD-015).
    pace: SendScheduler<Outgoing>,
    /// When this channel last sent a frame.
    last_send: Option<Instant>,
    /// A `Timer::Pace` is under way.
    pace_armed: bool,
    /// The transfers whose control message waits in `pace` for its slot.
    controls: HashSet<String>,
    /// Content envelopes (hex, as stored) that were handed to this channel and that the
    /// contact's end has not acknowledged yet. They are still in the stored queue: if the
    /// connection ends first, the next one sends them again.
    in_flight: HashSet<String>,
}

/// An ICE restart of a data connection that we started.
struct Restart {
    generation: u64,
    /// The peer's answer was applied.
    answered: bool,
}

impl Conn {
    /// An ICE restart, ours once answered or the peer's once applied, found its path: the
    /// connection came back to connected, or (begun while connected) its new generation
    /// selected a pair.
    fn complete_restart(&mut self, peer: &str) {
        if self.restart.as_ref().is_some_and(|r| r.answered) {
            tracing::info!(peer = %crate::short_id(peer), "ICE restart complete");
            self.restart = None;
            self.restarts_done += 1;
        } else if std::mem::take(&mut self.peer_restarting) {
            self.restarts_done += 1;
        }
    }

    fn is_open(&self) -> bool {
        self.dc.is_some()
    }

    fn is_verified(&self) -> bool {
        self.dc.is_some() && self.verified
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailReason {
    Timeout,
    IceFailed,
    Closed,
    Error,
    /// The peer's channel binding did not match (PNP-001-MUST-080).
    Binding,
    /// Relay-only, and the user's TURN server gave no relay candidate.
    NoRelay,
}

/// A call and its own WebRTC connection.
struct Call {
    info: CallInfo,
    handle: Option<RtcHandle>,
    /// Incoming: the caller's offer until we accept.
    remote_offer: Option<String>,
    remote_set: bool,
    pending_ice: Vec<RTCIceCandidateInit>,
    /// Our frames, until the connection exists (then a pump task owns it).
    frames_rx: Option<mpsc::UnboundedReceiver<OutFrame>>,
    /// The client's media end, until taken.
    media: Option<CallMedia>,
    media_tx: mpsc::Sender<MediaEvent>,
    /// Our first description (the `offer` or `answer`) went out; later ones are `reoffer` /
    /// `reanswer`.
    described: bool,
    /// The call is set up: the first offer and answer are applied on our side.
    established: bool,
    /// Our `reoffer` that is not answered yet.
    reoffer: Option<u64>,
    /// A `reoffer` / `reanswer` that could not be sent (no verified channel at that moment).
    unsent: Option<CallSignal>,
}

struct PeerState {
    /// Presence: `Some(true)` online, `Some(false)` offline, `None` unknown.
    online: Option<bool>,
    /// `online == Some(false)` came from a `peer_offline` answer, not a presence push: a soft
    /// verdict, re-probed with backoff (`reconnect`).
    offline_by_error: bool,
    /// The user asked to connect (opened the chat, pressed retry) and no verified channel
    /// has come of it yet: probed like a contact with queued messages.
    wanted: bool,
    /// The next connection attempt is a background probe: the path stays `Offline` unless
    /// the contact answers.
    quiet_probe: bool,
    conn: Option<Conn>,
    attempt: u32,
    failures: u32,
    path: PathState,
    fallback_armed: bool,
    retry_armed: bool,
    offer_waiting: bool,
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState {
            online: None,
            offline_by_error: false,
            wanted: false,
            quiet_probe: false,
            conn: None,
            attempt: 0,
            failures: 0,
            path: PathState::Unknown,
            fallback_armed: false,
            retry_armed: false,
            offer_waiting: false,
        }
    }
}

struct Engine {
    cfg: AppConfig,
    client: ParolNet,
    store: Store,
    state: State,
    me: String,
    my_pk: [u8; 32],
    input: mpsc::UnboundedSender<Input>,
    events: mpsc::UnboundedSender<AppEvent>,
    sig: SigHandle,
    relay: RelayState,
    registered: bool,
    peers: HashMap<String, PeerState>,
    pending_bootstrap: Option<PendingBootstrap>,
    pairing_until: Option<Instant>,
    /// Bootstraps under way, by peer (PNP-003 §4 from SECRET_SHARED on).
    pairings: HashMap<String, PairingSlot>,
    /// Bootstrap handshake nonces of the last 60 minutes (PNP-003-MUST-043).
    nonces: NonceTracker,
    /// Pairing codes made so far (picks the relay hint of the next one).
    codes_made: u64,
    stun: Vec<String>,
    /// How connections bind: one address, or every interface.
    gather: Gather,
    bind_ip: IpAddr,
    next_epoch: u64,
    offer_history: VecDeque<Instant>,
    signaling_backoff_until: Option<Instant>,
    rate_limit_hits: u32,
    calls: HashMap<String, Call>,
    /// Contacts the relay called offline without a presence push to say when that changes.
    probes: ProbeSchedule,
    /// When the pending `Timer::Probe` fires.
    probe_wake: Option<Instant>,
    /// When the user was last told their TURN server is unreachable.
    turn_notice_at: Option<Instant>,
    /// File transfers: workers, progress and limits (see `transfers`).
    xfer: transfers::Transfers,
}

pub(crate) async fn start(
    cfg: AppConfig,
) -> Result<(AppHandle, mpsc::UnboundedReceiver<AppEvent>), AppError> {
    crate::install_crypto_provider();
    if !(cfg.relay_url.starts_with("ws://") || cfg.relay_url.starts_with("wss://")) {
        return Err(AppError::Config(format!(
            "relay URL must be ws:// or wss://, not {}",
            cfg.relay_url
        )));
    }
    let store = Store::open(&cfg.data_dir, &cfg.key_storage)?;
    let identity = store.load_or_create_identity()?;
    let my_pk = identity.public_key_bytes();
    let me = hex::encode(identity.peer_id());

    let mut secret = identity.secret_bytes();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.zeroize();
    let signer: Signer = Arc::new(move |message: &[u8]| {
        use ed25519_dalek::Signer as _;
        signing_key.sign(message).to_bytes()
    });

    let client = ParolNet::from_identity(ParolNetConfig::default(), identity);
    let mut state = store.load_state()?;
    // A pairing that a restart interrupted is over: its half-made contact and its session
    // are removed before anything can use them.
    if state.forget_unfinished_pairings() {
        tracing::info!("removed what an unfinished pairing left behind");
        store.save_state(&state)?;
    }
    let mut sessions = Vec::with_capacity(state.sessions.len());
    for (pid, data) in &state.sessions {
        match (decode_32(pid), hex::decode(data)) {
            (Some(p), Ok(d)) => sessions.push((p, d)),
            _ => tracing::warn!(peer = %crate::short_id(pid), "skipping an unreadable session"),
        }
    }
    if !sessions.is_empty() {
        client
            .import_sessions(sessions)
            .map_err(|e| AppError::Store(format!("sessions: {e}")))?;
    }

    // One pinned address, or every interface (the driver picks and orders the addresses).
    let (gather, bind_ip) = match cfg.bind_ip {
        Some(ip) => (Gather::Bound, ip),
        None => (Gather::Interfaces, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    };

    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (events_tx, events_rx) = mpsc::unbounded_channel();

    let (sig_tx, mut sig_rx) = mpsc::unbounded_channel();
    let sig = signaling::spawn(
        cfg.relay_url.clone(),
        cfg.relay_trust_anchors.clone(),
        me.clone(),
        hex::encode(my_pk),
        signer,
        sig_tx,
    );
    {
        let input = input_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = sig_rx.recv().await {
                if input.send(Input::Sig(ev)).is_err() {
                    break;
                }
            }
        });
    }
    let stun = match &cfg.stun_servers {
        Some(list) => list.clone(),
        None => {
            let input = input_tx.clone();
            let url = cfg.relay_url.clone();
            tokio::spawn(async move {
                let stun = crate::ice::fetch_stun(&url).await;
                let _ = input.send(Input::Stun(stun));
            });
            Vec::new()
        }
    };
    {
        let input = input_tx.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(TICK);
            every.tick().await;
            loop {
                every.tick().await;
                if input.send(Input::Tick).is_err() {
                    break;
                }
            }
        });
    }

    if gather == Gather::Interfaces {
        // Watch the interfaces: a change restarts ICE instead of waiting for the old path
        // to time out.
        let input = input_tx.clone();
        tokio::spawn(async move {
            let mut monitor = NetworkMonitor::start(
                Arc::new(SystemNetwork),
                parolnet_rtc::net::DEFAULT_POLL_INTERVAL,
            );
            while monitor.changed().await.is_some() {
                if input.send(Input::NetworkChanged).is_err() {
                    break;
                }
            }
        });
    }

    let reconnect = cfg.reconnect.clone();
    let xfer = transfers::Transfers::new(&cfg);
    let handle = AppHandle {
        tx: input_tx.clone(),
        peer_id: me.clone(),
        public_key: hex::encode(my_pk),
    };
    let mut engine = Engine {
        cfg,
        client,
        store,
        state,
        me,
        my_pk,
        input: input_tx,
        events: events_tx,
        sig,
        relay: RelayState::Connecting,
        registered: false,
        peers: HashMap::new(),
        pending_bootstrap: None,
        pairing_until: None,
        pairings: HashMap::new(),
        nonces: NonceTracker::default(),
        codes_made: rand::thread_rng().r#gen(),
        stun,
        gather,
        bind_ip,
        next_epoch: 0,
        offer_history: VecDeque::new(),
        signaling_backoff_until: None,
        rate_limit_hits: 0,
        calls: HashMap::new(),
        probes: ProbeSchedule::new(reconnect, Instant::now()),
        probe_wake: None,
        turn_notice_at: None,
        xfer,
    };
    // Messages queued in an earlier run show as queued again.
    let queued: Vec<(String, u64)> = engine
        .state
        .queue
        .iter()
        .filter_map(|e| e.message_id.map(|id| (e.peer_id.clone(), id)))
        .collect();
    for (peer, id) in queued {
        if let Some(m) = engine.state.message_mut(&peer, id) {
            m.state = DeliveryState::Queued;
        }
    }
    tokio::spawn(engine.run(input_rx));
    Ok((handle, events_rx))
}

fn decode_32(hex_str: &str) -> Option<[u8; 32]> {
    let v = hex::decode(hex_str).ok()?;
    v.try_into().ok()
}

fn peer_id_of(hex_str: &str) -> Option<PeerId> {
    decode_32(hex_str).map(PeerId)
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

impl Engine {
    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Input>) {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Command(Command::Shutdown(reply)) => {
                    self.shutdown().await;
                    let _ = reply.send(());
                    return;
                }
                Input::Command(cmd) => self.on_command(cmd),
                Input::Sig(ev) => self.on_signaling(ev),
                Input::Stun(stun) => self.stun = stun,
                Input::RtcReady {
                    peer,
                    epoch,
                    result,
                } => self.on_rtc_ready(&peer, epoch, result),
                Input::Rtc { peer, epoch, event } => self.on_rtc_event(&peer, epoch, event),
                Input::Timer(t) => self.on_timer(t),
                Input::ContentAcked { peer, envelope } => self.on_content_acked(&peer, &envelope),
                Input::Tick => self.on_tick(),
                Input::NetworkChanged => self.on_network_changed(),
                Input::CallRtcReady { call_id, result } => self.on_call_ready(&call_id, result),
                Input::CallRtc { call_id, event } => self.on_call_rtc(&call_id, event),
                Input::FileChannel {
                    peer,
                    epoch,
                    dc,
                    label,
                    rx,
                } => self.on_file_channel(&peer, epoch, dc, &label, rx),
                Input::Transfer { id, event } => self.on_worker_event(&id, event),
                Input::OfferHashed {
                    peer,
                    result,
                    reply,
                } => self.on_offer_hashed(peer, result, reply),
            }
        }
        self.shutdown().await;
    }

    async fn shutdown(&mut self) {
        let calls: Vec<String> = self.calls.keys().cloned().collect();
        for id in calls {
            self.hangup_call(&id);
        }
        self.stop_transfers();
        let peers: Vec<String> = self.peers.keys().cloned().collect();
        for p in peers {
            self.drop_conn(&p);
        }
        self.persist_sessions();
        // Saves are committed on the store's own thread: wait for the last one.
        if let Err(e) = self.store.flush() {
            tracing::error!(%e, "flushing the store failed");
        }
        // The relay socket is closed properly: close frame, then TLS close_notify
        // (PNP-006-MUST-026).
        self.sig.stop().await;
    }

    // ── Small helpers ─────────────────────────────────────────────

    fn emit(&self, ev: AppEvent) {
        let _ = self.events.send(ev);
    }

    fn after(&self, delay: Duration, timer: Timer) {
        let input = self.input.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = input.send(Input::Timer(timer));
        });
    }

    fn save(&self) {
        if let Err(e) = self.store.save_state(&self.state) {
            tracing::error!(%e, "saving state failed");
            self.emit(AppEvent::Notice(format!("Could not save state: {e}")));
        }
    }

    /// Ratchet state changes on every encrypt / decrypt: export and save it.
    fn persist_sessions(&mut self) {
        self.state.sessions = self
            .client
            .export_sessions()
            .into_iter()
            .map(|(pid, data)| (hex::encode(pid), hex::encode(data)))
            .collect();
        self.save();
    }

    fn peer_mut(&mut self, peer: &str) -> &mut PeerState {
        self.peers.entry(peer.to_owned()).or_default()
    }

    fn set_path(&mut self, peer: &str, path: PathState) {
        let st = self.peer_mut(peer);
        if st.path != path {
            st.path = path;
            self.emit(AppEvent::Path {
                peer_id: peer.to_owned(),
                state: path,
            });
        }
    }

    fn is_contact(&self, peer: &str) -> bool {
        self.state.contact(peer).is_some()
    }

    fn pairing_open(&self) -> bool {
        self.pairing_until.is_some_and(|t| Instant::now() < t)
    }

    fn send_watch(&self) {
        if !self.registered {
            return;
        }
        let peer_ids = self
            .state
            .contacts
            .iter()
            .take(WATCH_MAX)
            .map(|c| c.peer_id.clone())
            .collect();
        self.sig.send(ClientFrame::Watch { peer_ids });
    }

    fn default_name(&self, peer: &str) -> String {
        self.cfg
            .default_contact_name
            .clone()
            .unwrap_or_else(|| crate::short_id(peer))
    }

    /// Add (or refresh) a contact. Returns it and whether it is new.
    fn upsert_contact(&mut self, peer: &str, identity_key: Option<String>) -> (Contact, bool) {
        if let Some(c) = self.state.contacts.iter_mut().find(|c| c.peer_id == peer) {
            if identity_key.is_some() && c.identity_key != identity_key {
                c.identity_key = identity_key;
            }
            return (c.clone(), false);
        }
        let contact = Contact {
            peer_id: peer.to_owned(),
            name: self.default_name(peer),
            identity_key,
            added_ms: now_ms(),
            sas_verified: false,
            pairing: None,
        };
        self.state.contacts.push(contact.clone());
        (contact, true)
    }

    // ── Commands ──────────────────────────────────────────────────

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::CreatePairingCode(reply) => {
                let _ = reply.send(self.create_pairing_code());
            }
            Command::PairWithCode(code, reply) => {
                let _ = reply.send(self.pair_with_code(&code));
            }
            Command::CancelPairingCode => self.close_pairing_code(),
            Command::ConfirmSas(peer, reply) => {
                let _ = reply.send(self.confirm_sas(&peer));
            }
            Command::RejectSas(peer) => self.reject_sas(&peer),
            Command::SendText(peer, text, reply) => {
                let _ = reply.send(self.send_text(&peer, &text));
            }
            Command::Messages(peer, reply) => {
                let _ = reply.send(self.state.messages.get(&peer).cloned().unwrap_or_default());
            }
            Command::Snapshot(reply) => {
                let _ = reply.send(self.snapshot());
            }
            Command::RenameContact(peer, name, reply) => {
                let result = match self.state.contacts.iter_mut().find(|c| c.peer_id == peer) {
                    Some(c) => {
                        c.name = name.trim().to_owned();
                        Ok(c.clone())
                    }
                    None => Err(AppError::UnknownContact(peer)),
                };
                if let Ok(c) = &result {
                    self.emit(AppEvent::ContactUpdated(c.clone()));
                    self.save();
                }
                let _ = reply.send(result);
            }
            Command::Connect(peer) => {
                // The user asked: offer now (the offer limiter still applies), and start the
                // soft-offline backoff over.
                let contact = self.is_contact(&peer);
                let st = self.peer_mut(&peer);
                st.attempt = 0;
                st.quiet_probe = false;
                st.wanted = contact && !st.conn.as_ref().is_some_and(Conn::is_verified);
                self.probes.restart(&peer, Instant::now());
                self.connect(&peer, true);
                self.arm_probe_wake();
            }
            Command::Disconnect(peer) => self.conn_failed(&peer, FailReason::Closed),
            Command::StartCall(peer, video, reply) => {
                let _ = reply.send(self.start_call(&peer, video));
            }
            Command::AcceptCall(id, reply) => {
                let _ = reply.send(self.accept_call(&id));
            }
            Command::RejectCall(id) => self.reject_call(&id),
            Command::Hangup(id) => self.hangup_call(&id),
            Command::TakeCallMedia(id, reply) => {
                let r = match self.calls.get_mut(&id) {
                    Some(c) => c.media.take().ok_or(AppError::UnknownCall(id)),
                    None => Err(AppError::UnknownCall(id)),
                };
                let _ = reply.send(r);
            }
            Command::SetCallVideo(id, enabled, reply) => {
                let _ = reply.send(self.set_call_video(&id, enabled));
            }
            Command::NetworkChanged => self.on_network_changed(),
            Command::TurnSettings(reply) => {
                let _ = reply.send(self.state.turn.clone());
            }
            Command::SetTurnSettings(settings, reply) => {
                let _ = reply.send(self.set_turn(settings));
            }
            Command::SetBandwidthMode(mode, reply) => {
                let _ = reply.send(self.set_bandwidth_mode(mode));
            }
            Command::OfferFile(peer, path, reply) => self.offer_file(peer, path, reply),
            Command::AcceptTransfer(id, reply) => {
                let _ = reply.send(self.accept_transfer(&id));
            }
            Command::DeclineTransfer(id, reply) => {
                let _ = reply.send(self.decline_transfer(&id));
            }
            Command::CancelTransfer(id, reply) => {
                let _ = reply.send(self.cancel_transfer(&id));
            }
            Command::Transfers(peer, reply) => {
                let _ = reply.send(self.list_transfers(peer.as_deref()));
            }
            Command::Shutdown(_) => unreachable!("handled in run"),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            peer_id: self.me.clone(),
            relay: self.relay.clone(),
            contacts: self
                .state
                .contacts
                .iter()
                .map(|c| ContactView {
                    contact: c.clone(),
                    path: self
                        .peers
                        .get(&c.peer_id)
                        .map(|p| p.path)
                        .unwrap_or(PathState::Unknown),
                    queued: self.state.queued_for(&c.peer_id),
                    ice_restarts: self
                        .peers
                        .get(&c.peer_id)
                        .and_then(|p| p.conn.as_ref())
                        .map_or(0, |conn| conn.restarts_done),
                })
                .collect(),
            pairing_open: self.pairing_open(),
            pairing_code: self.shown_code().map(|pb| pb.code.clone()),
            pairing_expires_ms: self.shown_code().map(|pb| pb.expires_ms),
            turn_configured: self.state.turn.is_some(),
            relay_only: self.state.turn.as_ref().is_some_and(|t| t.relay_only),
            bandwidth_mode: self.state.bandwidth_mode,
        }
    }

    /// The user chose a traffic-shaping mode (PNP-006-MUST-002): store it, move every
    /// connection's schedule to it and say what it costs (PNP-006-MUST-042).
    fn set_bandwidth_mode(&mut self, mode: BandwidthMode) -> String {
        self.state.bandwidth_mode = mode;
        for conn in self.peers.values_mut().filter_map(|p| p.conn.as_mut()) {
            conn.pace.set_mode(mode);
        }
        self.save();
        let warning = format!(
            "{} Direct connections to your contacts carry no cover traffic.",
            mode.bandwidth_warning()
        );
        self.emit(AppEvent::Notice(warning.clone()));
        warning
    }

    /// The user's TURN server and the ICE policy for a new connection. Nothing here comes
    /// from a relay: without the user's own settings there is no TURN at all.
    fn ice_setup(&self) -> (Option<TurnServer>, IcePolicy) {
        match &self.state.turn {
            Some(t) => (
                Some(TurnServer {
                    uri: t.uri.clone(),
                    username: t.username.clone(),
                    password: t.password.clone(),
                }),
                if t.relay_only {
                    IcePolicy::Relay
                } else {
                    IcePolicy::All
                },
            ),
            None => (None, IcePolicy::All),
        }
    }

    /// What every connection's configuration starts from: how it binds, STUN, and the
    /// user's TURN server and policy.
    fn rtc_base(&self) -> RtcConfig {
        let (turn, ice_policy) = self.ice_setup();
        RtcConfig {
            bind: SocketAddr::new(self.bind_ip, 0),
            gather: self.gather,
            stun_servers: self.stun.clone(),
            turn,
            ice_policy,
            ..Default::default()
        }
    }

    /// Store (or with `None` clear) the user's TURN server. It applies to every connection
    /// made from now on; data connections that exist are replaced at once so that turning
    /// relay-only on (or off) takes effect now, and contacts that had no path are tried
    /// again. A contact in a call keeps its connections until the next reconnect.
    fn set_turn(&mut self, settings: Option<TurnSettings>) -> Result<(), AppError> {
        let settings = settings.map(TurnSettings::validated).transpose()?;
        if self.state.turn == settings {
            return Ok(());
        }
        self.state.turn = settings;
        self.save();
        self.turn_notice_at = None;
        let in_call: Vec<String> = self
            .calls
            .values()
            .filter(|c| !c.info.is_over())
            .map(|c| c.info.peer_id.clone())
            .collect();
        let connected: Vec<String> = self
            .peers
            .iter()
            .filter(|(p, st)| st.conn.is_some() && !in_call.contains(p))
            .map(|(p, _)| p.clone())
            .collect();
        for peer in connected {
            self.drop_conn(&peer);
            let st = self.peer_mut(&peer);
            if st.online == Some(false) {
                continue; // a probe was under way; the next one uses the new settings
            }
            st.attempt = 0;
            st.failures = 0;
            self.set_path(&peer, PathState::Connecting);
            self.connect(&peer, true);
        }
        // Contacts that had no path (and may have run out of retries) get a fresh try.
        let stuck: Vec<String> = self
            .state
            .contacts
            .iter()
            .map(|c| c.peer_id.clone())
            .filter(|p| {
                self.peers.get(p).is_some_and(|st| {
                    st.conn.is_none()
                        && st.online != Some(false)
                        && st.path == PathState::NoDirectPath
                })
            })
            .collect();
        for peer in stuck {
            let st = self.peer_mut(&peer);
            st.attempt = 0;
            st.failures = 0;
            self.set_path(&peer, PathState::Connecting);
            self.connect(&peer, true);
        }
        Ok(())
    }

    fn send_text(&mut self, peer: &str, text: &str) -> Result<ChatMessage, AppError> {
        let pid = peer_id_of(peer).ok_or_else(|| AppError::UnknownContact(peer.to_owned()))?;
        if !self.client.has_session(&pid) {
            return Err(AppError::NoSession(peer.to_owned()));
        }
        if self.pairings.contains_key(peer) {
            return Ok(self.defer_text(peer, text));
        }
        let envelope = encrypt_for_peer(
            self.client.sessions(),
            &pid,
            msg_type::CHAT,
            text.as_bytes(),
            now_secs(),
            None,
        )
        .map_err(|e| AppError::Crypto(e.to_string()))?;
        let envelope = hex::encode(envelope);
        let id = self.state.alloc_message_id();
        let msg = ChatMessage {
            id,
            peer_id: peer.to_owned(),
            direction: Direction::Sent,
            text: text.to_owned(),
            timestamp_ms: now_ms(),
            state: DeliveryState::Queued,
        };
        // Every message waits in the stored queue for its send slot (PNP-006-MUST-007 /
        // MUST-008): on a verified channel that is the next slot, otherwise the first slot
        // of the next channel.
        let dropped = self.state.enqueue(
            QueuedEnvelope {
                peer_id: peer.to_owned(),
                envelope,
                created_ms: msg.timestamp_ms,
                message_id: Some(id),
            },
            now_ms(),
        );
        for (p, d) in dropped_owners(&self.state, dropped) {
            self.mark_message(&p, d, DeliveryState::Dropped);
        }
        if !self.has_verified_channel(peer) {
            self.connect(peer, false);
            // A soft-offline contact is now waited for: its next probe may be due sooner.
            self.arm_probe_wake();
        }
        self.state.push_message(msg.clone());
        self.persist_sessions();
        self.emit(AppEvent::Message(msg.clone()));
        self.pump(peer);
        Ok(msg)
    }

    fn mark_message(&mut self, peer: &str, id: u64, state: DeliveryState) {
        if let Some(m) = self.state.message_mut(peer, id) {
            m.state = state;
            self.emit(AppEvent::MessageState {
                peer_id: peer.to_owned(),
                id,
                state,
            });
        }
    }

    /// The contact's data channel is open and its binding has verified.
    fn has_verified_channel(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(Conn::is_verified)
    }

    /// Give a call signal or a file-transfer message to the contact's data channel once its
    /// binding has verified (PNP-001-SHOULD-018). False when there is no verified channel.
    /// It goes out in the channel's next send slot, ahead of queued content
    /// (PNP-006-MAY-002).
    fn send_on_channel(&mut self, peer: &str, envelope_hex: &str) -> bool {
        // Content waits for the pairing to complete: its session is about to be replaced.
        if self.pairings.contains_key(peer) {
            return false;
        }
        if !self.has_verified_channel(peer) {
            return false;
        }
        self.send_raw(peer, envelope_hex)
    }

    /// Give an envelope to the open data channel, verified or not (a pairing's handshake
    /// messages and our own binding). It goes out in the channel's next send slot.
    fn send_raw(&mut self, peer: &str, envelope_hex: &str) -> bool {
        self.send_frame(peer, Outgoing::Frame(DcFrame::chat(envelope_hex)))
    }

    /// Queue `out` for the open data channel's next free send slot. False when there is no
    /// open channel.
    fn send_frame(&mut self, peer: &str, out: Outgoing) -> bool {
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) else {
            return false;
        };
        if conn.dc.is_none() || conn.handle.is_none() {
            return false;
        }
        conn.pace.push(out);
        self.pump(peer);
        true
    }

    /// Ask for a send slot for the control message transfer `id` owes the contact
    /// (PNP-010). The message is built and sealed in the slot, from what the transfer owes
    /// then, and stays owed in the store until it has left. False when there is no open
    /// channel.
    fn queue_transfer_control(&mut self, peer: &str, id: &str) -> bool {
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) else {
            return false;
        };
        if conn.dc.is_none() || conn.handle.is_none() {
            return false;
        }
        if conn.controls.insert(id.to_owned()) {
            conn.pace.push(Outgoing::TransferControl(id.to_owned()));
        }
        self.pump(peer);
        true
    }

    /// A send slot for transfer `id`'s control message has been asked for on the contact's
    /// current connection and has not come up yet.
    fn transfer_control_queued(&self, peer: &str, id: &str) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(|c| c.controls.contains(id))
    }

    /// Write an envelope on the contact's verified data channel now. Only for the owner of
    /// the current send slot (`on_pace`).
    fn write_in_slot(&mut self, peer: &str, envelope_hex: &str) -> bool {
        if self.pairings.contains_key(peer) {
            return false;
        }
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) else {
            return false;
        };
        if !conn.is_verified() {
            return false;
        }
        let (Some(dc), Some(handle)) = (conn.dc, conn.handle.as_ref()) else {
            return false;
        };
        if handle.send_text(dc, DcFrame::chat(envelope_hex)).is_err() {
            return false;
        }
        conn.last_send = Some(Instant::now());
        true
    }

    /// How many of the contact's queued envelopes still wait for a send slot on this
    /// connection: content waits for the peer's binding (PNP-001-SHOULD-018) and for a
    /// pairing under way, and what is in flight has had its slot.
    fn content_waiting(&self, peer: &str) -> usize {
        if self.pairings.contains_key(peer) {
            return 0;
        }
        let Some(conn) = self.peers.get(peer).and_then(|p| p.conn.as_ref()) else {
            return 0;
        };
        if !conn.is_verified() {
            return 0;
        }
        self.state
            .queue
            .iter()
            .filter(|e| e.peer_id == peer && !conn.in_flight.contains(&e.envelope))
            .count()
    }

    /// Arm the data channel's next send slot when something waits for one (PNP-006 §4.1,
    /// §4.2, §4.4). The wait is what is left of the padding interval since the channel's
    /// last send, plus a fresh jitter: no frame leaves without one.
    fn pump(&mut self, peer: &str) {
        let content = self.content_waiting(peer);
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) else {
            return;
        };
        if !conn.is_open() || conn.pace_armed {
            return;
        }
        if conn.pace.is_empty() && content == 0 {
            return;
        }
        let since = conn.last_send.map(|at| at.elapsed());
        let delay = conn.pace.next_delay_with_backlog(since, content);
        conn.pace_armed = true;
        let epoch = conn.epoch;
        self.after(
            delay,
            Timer::Pace {
                peer: peer.to_owned(),
                epoch,
            },
        );
    }

    /// A send slot: exactly one frame leaves (PNP-006-MUST-005). Channel set-up frames,
    /// call signals and file-transfer messages first, in the order they were given; then
    /// the oldest queued content (PNP-006-MUST-009).
    fn on_pace(&mut self, peer: &str, epoch: u64) {
        let Some(conn) = self.conn_mut(peer, epoch) else {
            return;
        };
        conn.pace_armed = false;
        let (Some(dc), Some(handle)) = (conn.dc, conn.handle.as_ref()) else {
            return;
        };
        // Cover traffic is off here, so a slot with nothing of the channel's own to carry
        // is free for content.
        let used = match conn.pace.on_slot() {
            Some(SendChoice::Real(Outgoing::Frame(frame))) => {
                conn.last_send = Some(Instant::now());
                if handle.send_text(dc, frame).is_err() {
                    // The connection's task has ended; its `Closed` event follows.
                    return;
                }
                true
            }
            Some(SendChoice::Real(Outgoing::TransferControl(id))) => {
                conn.controls.remove(&id);
                self.send_owed_transfer_control(peer, &id)
            }
            _ => false,
        };
        if !used {
            self.send_next_content(peer, epoch);
        }
        self.pump(peer);
    }

    /// Hand the contact's oldest queued envelope that has not had a slot on this connection
    /// to its data channel. The envelope stays in the stored queue, and its message
    /// `Queued`, until the contact's end has acknowledged it (`on_content_acked`): what a
    /// connection takes with it when it ends is sent again on the next one.
    fn send_next_content(&mut self, peer: &str, epoch: u64) {
        if self.content_waiting(peer) == 0 {
            return;
        }
        let Some(conn) = self
            .peers
            .get_mut(peer)
            .and_then(|p| p.conn.as_mut())
            .filter(|c| c.epoch == epoch)
        else {
            return;
        };
        let (Some(dc), Some(handle)) = (conn.dc, conn.handle.as_ref()) else {
            return;
        };
        let Some(entry) = self
            .state
            .queue
            .iter()
            .find(|e| e.peer_id == peer && !conn.in_flight.contains(&e.envelope))
        else {
            return;
        };
        let Ok(acked) = handle.send_text_acked(dc, DcFrame::chat(&entry.envelope)) else {
            // The connection's task has ended: the envelope waits for the next channel.
            return;
        };
        conn.last_send = Some(Instant::now());
        conn.in_flight.insert(entry.envelope.clone());
        let (input, peer, envelope) = (self.input.clone(), peer.to_owned(), entry.envelope.clone());
        tokio::spawn(async move {
            // An error is a connection that ended first: nothing was acknowledged.
            if acked.await.is_ok() {
                let _ = input.send(Input::ContentAcked { peer, envelope });
            }
        });
    }

    /// The contact's end acknowledged a content envelope (its SCTP did; the channel is
    /// reliable): only now does it leave the stored queue and its message become `Sent`.
    fn on_content_acked(&mut self, peer: &str, envelope: &str) {
        if let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) {
            conn.in_flight.remove(envelope);
        }
        // Not there any more: evicted by the queue's limits, or the contact was paired
        // again or removed in the meantime.
        let Some(at) = self
            .state
            .queue
            .iter()
            .position(|e| e.peer_id == peer && e.envelope == envelope)
        else {
            return;
        };
        if let Some(id) = self.state.queue.remove(at).and_then(|e| e.message_id) {
            self.mark_message(peer, id, DeliveryState::Sent);
        }
        self.save();
    }

    /// PNP-001-MUST-079: our CHANNEL_BINDING, once the channel is open and we hold a session.
    fn send_binding(&mut self, peer: &str) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        if !self.client.has_session(&pid) {
            return; // the presenter, before the scanner's bootstrap envelope
        }
        let Some(conn) = self.peers.get(peer).and_then(|p| p.conn.as_ref()) else {
            return;
        };
        if !conn.is_open() || conn.binding_sent {
            return;
        }
        let (Some(local), Some(remote)) = (conn.local_sdp.as_deref(), conn.remote_sdp.as_deref())
        else {
            tracing::warn!(peer = %crate::short_id(peer), "no descriptions to bind");
            return;
        };
        let body = match ChannelBinding::from_sdps(local, remote) {
            Ok(b) => b.encode(),
            Err(e) => {
                tracing::warn!(peer = %crate::short_id(peer), %e, "cannot bind the channel");
                return;
            }
        };
        let envelope = match encrypt_for_peer(
            self.client.sessions(),
            &pid,
            msg_type::CHANNEL_BINDING,
            &body,
            now_secs(),
            None,
        ) {
            Ok(e) => hex::encode(e),
            Err(e) => {
                tracing::warn!(peer = %crate::short_id(peer), %e, "binding encrypt failed");
                return;
            }
        };
        if self.send_raw(peer, &envelope) {
            if let Some(c) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) {
                c.binding_sent = true;
            }
            self.persist_sessions();
        }
    }

    /// PNP-001-MUST-080: check the peer's binding against our view of the connection.
    fn on_binding(&mut self, peer: &str, body: &[u8]) {
        let Some(conn) = self.peers.get(peer).and_then(|p| p.conn.as_ref()) else {
            return;
        };
        if !conn.is_open() || conn.verified {
            return;
        }
        let result = match (conn.local_sdp.as_deref(), conn.remote_sdp.as_deref()) {
            (Some(local), Some(remote)) => {
                ChannelBinding::decode(body).and_then(|b| b.verify(local, remote))
            }
            _ => Err(BindingError::NoFingerprint),
        };
        match result {
            Ok(()) => {
                if let Some(c) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) {
                    c.verified = true;
                }
                let st = self.peer_mut(peer);
                st.attempt = 0;
                st.failures = 0;
                st.wanted = false;
                tracing::info!(peer = %crate::short_id(peer), "direct channel verified");
                // A presenter whose session appeared with this very envelope binds now.
                self.send_binding(peer);
                // While the contact's pairing is still under way the path is not usable
                // yet: it is shown as direct when the pairing completes.
                if !self.pairings.contains_key(peer) {
                    self.set_path(peer, PathState::Direct);
                    self.flush_queue(peer);
                    self.transfers_on_verified(peer);
                    self.flush_call_signals(peer);
                }
            }
            Err(e) => {
                tracing::warn!(peer = %crate::short_id(peer), %e, "channel binding refused");
                let name = self
                    .state
                    .contact(peer)
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| crate::short_id(peer));
                self.emit(AppEvent::Notice(format!(
                    "The direct connection to {name} failed its end-to-end check ({e}). \
                     Someone between you, such as the relay, may be interfering; it was closed."
                )));
                self.conn_failed(peer, FailReason::Binding);
            }
        }
    }

    /// The channel verified: queued content starts to drain, one envelope per send slot.
    fn flush_queue(&mut self, peer: &str) {
        self.pump(peer);
    }

    // ── Signaling ─────────────────────────────────────────────────

    fn on_signaling(&mut self, ev: SigEvent) {
        match ev {
            SigEvent::Connecting => {
                if !matches!(self.relay, RelayState::Connecting) {
                    self.relay = RelayState::Connecting;
                    self.emit(AppEvent::Relay(self.relay.clone()));
                }
            }
            SigEvent::Registered { profile } => {
                self.registered = true;
                self.rate_limit_hits = 0;
                self.relay = RelayState::Registered { profile };
                self.emit(AppEvent::Relay(self.relay.clone()));
                self.send_watch();
                // Probe contacts we hold messages for (presence only comes from mutual
                // watchers, so a fresh pairing gets no push).
                let waiting: Vec<String> = self
                    .state
                    .contacts
                    .iter()
                    .filter(|c| self.state.waits_for(&c.peer_id))
                    .map(|c| c.peer_id.clone())
                    .collect();
                for p in waiting {
                    self.connect(&p, false);
                }
                self.flush_unsent_descriptions();
                self.run_probes();
            }
            SigEvent::Disconnected { reason } => {
                self.registered = false;
                self.relay = RelayState::Disconnected { reason };
                self.emit(AppEvent::Relay(self.relay.clone()));
            }
            SigEvent::Frame(frame) => self.on_frame(frame),
        }
    }

    fn on_frame(&mut self, frame: ServerFrame) {
        match frame {
            ServerFrame::Presence { peer_id, online } => self.on_presence(&peer_id, online),
            ServerFrame::Signal {
                kind,
                from,
                payload,
            } => self.on_signal(kind, &from, &payload),
            ServerFrame::Error {
                code,
                message,
                peer_id,
            } => match code.as_str() {
                "peer_offline" => {
                    if let Some(peer) = peer_id {
                        let st = self.peer_mut(&peer);
                        // After a presence push said offline the relay tells us when that
                        // changes. Otherwise nobody will: the verdict is soft and the
                        // contact is probed again with backoff.
                        let pushed = st.online == Some(false) && !st.offline_by_error;
                        st.online = Some(false);
                        st.offline_by_error = !pushed;
                        let open = st.conn.as_ref().is_some_and(Conn::is_open);
                        if !open {
                            self.drop_conn(&peer);
                            self.set_path(&peer, PathState::Offline);
                        }
                        if !pushed && self.is_contact(&peer) {
                            let jitter = rand::thread_rng().r#gen::<f64>();
                            self.probes.note_offline(&peer, Instant::now(), jitter);
                            self.arm_probe_wake();
                        }
                    }
                }
                "rate_limited" => {
                    let wait = Duration::from_secs(60)
                        .saturating_mul(1 << self.rate_limit_hits.min(4))
                        .min(Duration::from_secs(600));
                    self.rate_limit_hits += 1;
                    self.signaling_backoff_until = Some(Instant::now() + wait);
                    tracing::warn!(?wait, "signaling rate-limited; pausing offers");
                }
                _ => tracing::debug!(%code, %message, "relay error"),
            },
            ServerFrame::Challenge { .. }
            | ServerFrame::Registered { .. }
            | ServerFrame::Pong
            | ServerFrame::Other(_) => {}
        }
    }

    fn on_presence(&mut self, peer: &str, online: bool) {
        // A push is authoritative either way: the relay reports the next change too.
        self.probes.clear(peer);
        let st = self.peer_mut(peer);
        let was = st.online;
        st.online = Some(online);
        st.offline_by_error = false;
        st.quiet_probe = false;
        if online {
            if was != Some(true) {
                st.attempt = 0;
                st.failures = 0;
            }
            let has_conn = st.conn.is_some();
            if !has_conn {
                if self.is_contact(peer) {
                    self.connect(peer, false);
                }
                let path = self.peers[peer].path;
                if matches!(path, PathState::Offline | PathState::Unknown) {
                    self.set_path(peer, PathState::Connecting);
                }
            }
        } else {
            let open = st.conn.as_ref().is_some_and(Conn::is_open);
            if !open {
                self.drop_conn(peer);
                self.set_path(peer, PathState::Offline);
            }
        }
    }

    fn signal(&self, kind: SignalKind, to: &str, payload: String) -> bool {
        if !self.registered {
            return false;
        }
        self.sig.send(kind.frame(to.to_owned(), payload));
        true
    }

    /// Accepting an offer shows our IP address to its sender: only contacts, a peer we
    /// already connect to, or anyone while our pairing code is valid.
    fn offer_allowed(&self, from: &str) -> bool {
        self.is_contact(from)
            || self.peers.get(from).is_some_and(|p| p.conn.is_some())
            || self.pairing_open()
    }

    fn on_signal(&mut self, kind: SignalKind, from: &str, payload: &str) {
        if !is_peer_id(from) || from == self.me {
            return;
        }
        match kind {
            SignalKind::Offer => {
                if !self.offer_allowed(from) {
                    tracing::info!(peer = %crate::short_id(from), "ignoring an offer from a non-contact");
                    return;
                }
                let Some(offer) = serde_json::from_str::<SdpJson>(payload)
                    .ok()
                    .filter(|s| s.sdp_type == "offer")
                    .and_then(|s| RTCSessionDescription::offer(s.sdp).ok())
                else {
                    tracing::debug!("malformed offer");
                    return;
                };
                // An offer for a connection we hold may be an ICE restart of it: the
                // verified connection, with the certificate its binding covers. It is
                // applied in place. When it crosses a restart of ours the designated
                // initiator's stands: that side drops the other's offer, the other side
                // drops its own and answers. Anything else is an offer for a new connection.
                let designated = should_initiate(&self.me, from);
                let renegotiation = self.cfg.renegotiation;
                if let Some(conn) = self.peers.get_mut(from).and_then(|p| p.conn.as_mut()) {
                    let decision = crate::wire::on_restart_offer(
                        renegotiation,
                        conn.is_verified(),
                        same_dtls_session(conn.remote_sdp.as_deref(), &offer.sdp),
                        conn.restart.is_some(),
                        designated,
                    );
                    match decision {
                        RestartOffer::NewConnection => {}
                        RestartOffer::KeepOurs => {
                            tracing::debug!(peer = %crate::short_id(from), "crossing ICE restarts; keeping ours");
                            return;
                        }
                        RestartOffer::Apply | RestartOffer::Yield => {
                            if decision == RestartOffer::Yield {
                                conn.restart = None;
                                conn.unsent = None;
                            }
                            tracing::info!(peer = %crate::short_id(from), "ICE restart offered by the contact");
                            if let Some(h) = conn.handle.as_ref()
                                && h.set_remote_description(offer).is_ok()
                            {
                                conn.peer_restarting = true;
                            }
                            self.mark_online(from);
                            return;
                        }
                    }
                }
                if let Some(conn) = self.peers.get(from).and_then(|p| p.conn.as_ref()) {
                    if conn.initiator && !conn.remote_set && should_initiate(&self.me, from) {
                        // Glare: the designated initiator keeps its own offer.
                        tracing::debug!(peer = %crate::short_id(from), "glare; keeping our offer");
                        return;
                    }
                    // Glare where we yield, or the peer restarted: take the new offer.
                    self.drop_conn(from);
                }
                self.mark_online(from);
                self.start_conn(from, false, Some(offer));
            }
            SignalKind::Answer => {
                let Some(conn) = self.peers.get_mut(from).and_then(|p| p.conn.as_mut()) else {
                    return;
                };
                let restarting = conn.restart.as_ref().is_some_and(|r| !r.answered);
                if !restarting && (!conn.initiator || conn.remote_set) {
                    return;
                }
                let Some(answer) = serde_json::from_str::<SdpJson>(payload)
                    .ok()
                    .filter(|s| s.sdp_type == "answer")
                    .and_then(|s| RTCSessionDescription::answer(s.sdp).ok())
                else {
                    tracing::debug!("malformed answer");
                    return;
                };
                if restarting {
                    // The answer to our ICE restart. It has to be the session we hold: an
                    // answer with another certificate comes from a connection the contact
                    // made anew, and ours is rebuilt to meet it.
                    if !same_dtls_session(conn.remote_sdp.as_deref(), &answer.sdp) {
                        tracing::info!(peer = %crate::short_id(from), "the restart was answered by another session; rebuilding");
                        self.conn_failed(from, FailReason::Error);
                        return;
                    }
                    if let Some(h) = conn.handle.as_ref()
                        && h.set_remote_description(answer).is_ok()
                        && let Some(restart) = conn.restart.as_mut()
                    {
                        restart.answered = true;
                    }
                    return;
                }
                let answer_sdp = answer.sdp.clone();
                if let Some(h) = conn.handle.as_ref()
                    && h.set_remote_description(answer).is_ok()
                {
                    conn.remote_set = true;
                    conn.remote_sdp = Some(answer_sdp);
                    for c in conn.pending_ice.drain(..) {
                        let _ = h.add_remote_candidate(c);
                    }
                }
                // An answer means the contact is there (a probe found it).
                self.mark_online(from);
                if self.peers[from].path == PathState::Offline {
                    self.set_path(from, PathState::Connecting);
                }
            }
            SignalKind::Ice => {
                let Some(conn) = self.peers.get_mut(from).and_then(|p| p.conn.as_mut()) else {
                    return;
                };
                let Ok(candidate) = serde_json::from_str::<RTCIceCandidateInit>(payload) else {
                    return;
                };
                if candidate.candidate.is_empty() {
                    return; // end-of-candidates
                }
                match (conn.remote_set, conn.handle.as_ref()) {
                    (true, Some(h)) => {
                        let _ = h.add_remote_candidate(candidate);
                    }
                    _ if conn.pending_ice.len() < PENDING_ICE_MAX => {
                        conn.pending_ice.push(candidate)
                    }
                    _ => {}
                }
            }
        }
    }

    // ── Connections ───────────────────────────────────────────────

    /// Ask for a data channel to `peer`. No-op while one is open or being set up. The
    /// designated initiator offers; the other side waits [`OFFER_FALLBACK`] for that offer
    /// and then offers itself. `force` offers now (pairing, retries, user intent).
    fn connect(&mut self, peer: &str, force: bool) {
        if peer == self.me || !is_peer_id(peer) || !self.registered {
            return;
        }
        let me = self.me.clone();
        let st = self.peer_mut(peer);
        if st.conn.is_some() {
            return;
        }
        if st.online == Some(false) && !force {
            return;
        }
        if force || should_initiate(&me, peer) {
            self.schedule_offer(peer);
        } else if !st.fallback_armed {
            st.fallback_armed = true;
            let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..2000));
            self.after(
                OFFER_FALLBACK + jitter,
                Timer::OfferFallback {
                    peer: peer.to_owned(),
                },
            );
        }
    }

    fn schedule_offer(&mut self, peer: &str) {
        if self.peers.get(peer).is_some_and(|p| p.offer_waiting) {
            return;
        }
        let now = Instant::now();
        let mut wait = self
            .signaling_backoff_until
            .map(|t| t.saturating_duration_since(now))
            .unwrap_or_default();
        if wait.is_zero() {
            while self
                .offer_history
                .front()
                .is_some_and(|t| now.duration_since(*t) >= OFFER_WINDOW)
            {
                self.offer_history.pop_front();
            }
            if self.offer_history.len() < OFFERS_PER_WINDOW {
                self.offer_history.push_back(now);
            } else {
                wait = OFFER_WINDOW
                    .saturating_sub(now.duration_since(self.offer_history[0]))
                    .max(Duration::from_millis(1));
            }
        }
        if wait.is_zero() {
            self.start_conn(peer, true, None);
        } else {
            self.peer_mut(peer).offer_waiting = true;
            self.after(
                wait,
                Timer::OfferSlot {
                    peer: peer.to_owned(),
                },
            );
        }
    }

    fn start_conn(
        &mut self,
        peer: &str,
        initiator: bool,
        remote_offer: Option<RTCSessionDescription>,
    ) {
        self.next_epoch += 1;
        let epoch = self.next_epoch;
        let mut pace = SendScheduler::new(self.state.bandwidth_mode);
        pace.set_cover(false);
        let st = self.peer_mut(peer);
        st.conn = Some(Conn {
            epoch,
            handle: None,
            initiator,
            remote_offer,
            remote_set: false,
            pending_ice: Vec::new(),
            dc: None,
            last_state: None,
            local_sdp: None,
            remote_sdp: None,
            binding_sent: false,
            verified: false,
            described: false,
            peer_restarts: false,
            restart: None,
            unsent: None,
            restarts_done: 0,
            peer_restarting: false,
            pace,
            last_send: None,
            pace_armed: false,
            controls: HashSet::new(),
            in_flight: HashSet::new(),
        });
        st.fallback_armed = false;
        // A background probe of a contact believed offline shows nothing until it is answered.
        let quiet = std::mem::take(&mut st.quiet_probe) && st.online == Some(false);
        if !quiet && !matches!(st.path, PathState::NoDirectPath | PathState::BindingFailed) {
            self.set_path(peer, PathState::Connecting);
        }
        let config = RtcConfig {
            data_channel: initiator.then(|| DATA_CHANNEL_LABEL.to_owned()),
            // When ICE restarts cross, the designated initiator's stands.
            polite: !should_initiate(&self.me, peer),
            // No RTP here, and transfer records are 64 KiB each: a short queue, so that a
            // reader that falls behind holds the connection back instead of filling memory.
            event_capacity: 64,
            ..self.rtc_base()
        };
        let input = self.input.clone();
        let peer_owned = peer.to_owned();
        tokio::spawn(async move {
            match parolnet_rtc::spawn(config).await {
                Ok((handle, events)) => {
                    let ready = Input::RtcReady {
                        peer: peer_owned.clone(),
                        epoch,
                        result: Ok(handle),
                    };
                    if input.send(ready).is_err() {
                        return;
                    }
                    // Everything goes to the core, except the messages of transfer
                    // channels, which go to their workers.
                    crate::transfer::forward_events(events, input, peer_owned, epoch).await;
                }
                Err(e) => {
                    let _ = input.send(Input::RtcReady {
                        peer: peer_owned,
                        epoch,
                        result: Err(e.into()),
                    });
                }
            }
        });
        self.after(
            CONNECT_TIMEOUT,
            Timer::ConnectTimeout {
                peer: peer.to_owned(),
                epoch,
            },
        );
    }

    fn conn_mut(&mut self, peer: &str, epoch: u64) -> Option<&mut Conn> {
        self.peers
            .get_mut(peer)?
            .conn
            .as_mut()
            .filter(|c| c.epoch == epoch)
    }

    fn on_rtc_ready(&mut self, peer: &str, epoch: u64, result: Result<RtcHandle, StartFailure>) {
        let handle = match result {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(peer = %crate::short_id(peer), e = %e.message, "could not start a connection");
                if self.conn_mut(peer, epoch).is_some() {
                    if e.no_relay {
                        self.notice_no_relay(&e.message);
                        self.conn_failed(peer, FailReason::NoRelay);
                    } else {
                        self.conn_failed(peer, FailReason::Error);
                    }
                }
                return;
            }
        };
        let Some(conn) = self.conn_mut(peer, epoch) else {
            tokio::spawn(handle.close());
            return;
        };
        let ok = if conn.initiator {
            handle.create_offer().is_ok()
        } else if let Some(offer) = conn.remote_offer.take() {
            let offer_sdp = offer.sdp.clone();
            let ok = handle.set_remote_description(offer).is_ok();
            conn.remote_set = ok;
            if ok {
                conn.remote_sdp = Some(offer_sdp);
            }
            for c in conn.pending_ice.drain(..) {
                let _ = handle.add_remote_candidate(c);
            }
            ok
        } else {
            false
        };
        conn.handle = Some(handle);
        if !ok {
            self.conn_failed(peer, FailReason::Error);
        }
    }

    fn on_rtc_event(&mut self, peer: &str, epoch: u64, event: RtcEvent) {
        let me = self.me.clone();
        let renegotiation = self.cfg.renegotiation;
        let Some(conn) = self.conn_mut(peer, epoch) else {
            return;
        };
        match event {
            RtcEvent::LocalDescription(desc) => {
                // The first description is the one the channel binding covers; later ones
                // (same certificate, new ICE credentials) belong to an ICE restart.
                let first = !conn.described;
                if first {
                    conn.described = true;
                    conn.local_sdp = Some(desc.sdp.clone());
                }
                let is_offer = desc.sdp_type == RTCSdpType::Offer;
                let payload = serde_json::to_string(&SdpJson {
                    sdp_type: if is_offer { "offer" } else { "answer" }.to_owned(),
                    sdp: desc.sdp.clone(),
                })
                .unwrap_or_default();
                let kind = if is_offer {
                    SignalKind::Offer
                } else {
                    SignalKind::Answer
                };
                if !self.signal(kind, peer, payload.clone()) {
                    if first {
                        tracing::debug!(peer = %crate::short_id(peer), "relay down; description not sent");
                        self.conn_failed(peer, FailReason::Error);
                    } else if let Some(conn) = self.conn_mut(peer, epoch) {
                        // The network change that asked for the restart usually took the
                        // relay's socket with it: the description goes out when it is back.
                        conn.unsent = Some((kind, payload));
                    }
                    return;
                }
                if first && is_offer {
                    self.after(
                        ANSWER_TIMEOUT,
                        Timer::AnswerTimeout {
                            peer: peer.to_owned(),
                            epoch,
                        },
                    );
                }
            }
            RtcEvent::ConnectionState(state) => {
                conn.last_state = Some(state);
                let (verified, restarts) = (conn.is_verified(), conn.peer_restarts);
                match state {
                    RTCPeerConnectionState::Disconnected => {
                        // No path right now: say so, whatever happens next.
                        if verified {
                            self.set_path(peer, PathState::Connecting);
                        }
                        if verified && restarts {
                            // Look for a new path before giving the connection up; the
                            // restart's own deadline replaces the grace period.
                            self.restart_conn(peer);
                        } else {
                            self.after(
                                DISCONNECT_GRACE,
                                Timer::DisconnectGrace {
                                    peer: peer.to_owned(),
                                    epoch,
                                },
                            );
                        }
                    }
                    RTCPeerConnectionState::Connected => {
                        conn.complete_restart(peer);
                        if verified {
                            self.set_path(peer, PathState::Direct);
                            self.flush_call_signals(peer);
                            // What a transfer owed the contact while there was no path.
                            self.transfers_on_verified(peer);
                        }
                    }
                    RTCPeerConnectionState::Failed => self.conn_failed(peer, FailReason::IceFailed),
                    RTCPeerConnectionState::Closed => self.conn_failed(peer, FailReason::Closed),
                    _ => {}
                }
            }
            RtcEvent::DataChannelOpen { id, label } => {
                if label != DATA_CHANNEL_LABEL || conn.dc.is_some() {
                    tracing::debug!(%label, "ignoring an extra data channel");
                    return;
                }
                conn.dc = Some(id);
                self.send_frame(peer, Outgoing::Frame(DcFrame::identity(&me, renegotiation)));
                self.mark_online(peer);
                tracing::info!(peer = %crate::short_id(peer), "data channel open; binding");
                // PNP-001 §10.5.1: the bootstrap-completing envelope first (we scanned the
                // peer's code), then our binding. Everything else waits for the peer's binding.
                self.flush_pairing(peer);
                self.send_binding(peer);
                self.after(
                    BINDING_TIMEOUT,
                    Timer::BindingTimeout {
                        peer: peer.to_owned(),
                        epoch,
                    },
                );
            }
            RtcEvent::DataChannelMessage { id, payload } => {
                if conn.dc == Some(id) {
                    self.on_data(peer, &payload);
                }
            }
            RtcEvent::Closed { error } => {
                tracing::debug!(peer = %crate::short_id(peer), ?error, "connection task ended");
                let reason = if error.is_some() {
                    FailReason::Error
                } else {
                    FailReason::Closed
                };
                self.conn_failed(peer, reason);
            }
            // A restart begun while connected stays connected (W3C webrtc-pc 5.6.4, engine
            // v0.22.0+brainwires.6): it completes when the new generation selects a pair.
            RtcEvent::SelectedCandidatePairChanged => conn.complete_restart(peer),
            RtcEvent::IceConnectionState(_)
            | RtcEvent::Track { .. }
            | RtcEvent::Rtp { .. }
            | RtcEvent::KeyframeRequested
            | RtcEvent::DataChannelClose { .. }
            | RtcEvent::DataChannelBufferedLow { .. }
            | RtcEvent::RemoteMedia { .. }
            | RtcEvent::LocalMedia { .. }
            | RtcEvent::TargetBitrate { .. }
            | RtcEvent::Quality(_)
            | RtcEvent::RemoteOfferIgnored => {}
        }
    }

    // ── Network changes ───────────────────────────────────────────

    /// The machine's addresses changed. The relay is asked at once whether its socket still
    /// lives; every verified connection whose contact takes an ICE restart gets one, and so
    /// does a call. A contact whose app does not restart is left alone: its connection
    /// either still works or fails and is rebuilt as before.
    fn on_network_changed(&mut self) {
        tracing::info!("the network changed");
        self.sig.nudge();
        let restartable: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, st)| {
                st.conn
                    .as_ref()
                    .is_some_and(|c| c.is_verified() && c.peer_restarts)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in restartable {
            self.restart_conn(&peer);
        }
        let calls: Vec<String> = self.calls.keys().cloned().collect();
        for call_id in calls {
            self.restart_call(&call_id);
        }
    }

    /// Restart ICE on the contact's data connection (no-op while one is under way). The
    /// session and the path it has are kept until the restart finds a new one; without an
    /// answer and a connection in [`RESTART_TIMEOUT`] the connection is rebuilt.
    fn restart_conn(&mut self, peer: &str) {
        self.next_epoch += 1;
        let generation = self.next_epoch;
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) else {
            return;
        };
        if conn.restart.is_some() || !conn.is_verified() || !conn.peer_restarts {
            return;
        }
        let Some(h) = conn.handle.as_ref() else {
            return;
        };
        if h.restart_ice().is_err() {
            return;
        }
        tracing::info!(peer = %crate::short_id(peer), "restarting ICE");
        conn.restart = Some(Restart {
            generation,
            answered: false,
        });
        let epoch = conn.epoch;
        self.after(
            RESTART_TIMEOUT,
            Timer::RestartTimeout {
                peer: peer.to_owned(),
                epoch,
                generation,
            },
        );
    }

    /// The relay is back: send the restart descriptions made while it was away.
    fn flush_unsent_descriptions(&mut self) {
        let unsent: Vec<(String, SignalKind, String)> = self
            .peers
            .iter_mut()
            .filter_map(|(peer, st)| {
                let (kind, payload) = st.conn.as_mut()?.unsent.take()?;
                Some((peer.clone(), kind, payload))
            })
            .collect();
        for (peer, kind, payload) in unsent {
            self.signal(kind, &peer, payload);
        }
    }

    fn drop_conn(&mut self, peer: &str) {
        let Some(mut conn) = self.peers.get_mut(peer).and_then(|p| p.conn.take()) else {
            return;
        };
        let Some(h) = conn.handle.take() else {
            return;
        };
        // We are closing the channel: what still waits for a send slot (a call's hang-up,
        // say) goes out now, since there is no later slot to give it. Queued content and
        // the control messages transfers owe are not touched; they stay in the store for
        // the next channel.
        if let Some(dc) = conn.dc {
            for out in conn.pace.drain() {
                if let Outgoing::Frame(frame) = out {
                    let _ = h.send_text(dc, frame);
                }
            }
        }
        tokio::spawn(h.close());
    }

    fn conn_failed(&mut self, peer: &str, reason: FailReason) {
        let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.take()) else {
            return;
        };
        let was_open = conn.is_open();
        let was_initiator = conn.initiator;
        if let Some(h) = conn.handle {
            tokio::spawn(h.close());
        }
        // A bootstrap whose handshake was under way on this connection is over: its
        // messages are not repeated on another one.
        if self.pairings.get(peer).is_some_and(|slot| slot.started) {
            self.abort_pairing(peer, "the connection was lost during pairing");
        }
        tracing::info!(peer = %crate::short_id(peer), ?reason, was_open, "connection ended");
        let st = self.peer_mut(peer);
        if st.online == Some(false) {
            self.set_path(peer, PathState::Offline);
            return;
        }
        if !was_open {
            st.failures += 1;
        }
        let failures = st.failures;
        let path = if reason == FailReason::Binding {
            PathState::BindingFailed
        } else if reason == FailReason::NoRelay {
            // Relay-only never falls back to a direct path.
            PathState::NoDirectPath
        } else if was_open {
            PathState::Unknown
        } else if (reason == FailReason::IceFailed && failures >= 1)
            || (reason == FailReason::Timeout && failures >= 2)
        {
            PathState::NoDirectPath
        } else {
            PathState::Connecting
        };
        self.set_path(peer, path);
        if was_open {
            self.peer_mut(peer).attempt = 0;
        }
        self.schedule_retry(peer, was_initiator);
    }

    /// Tell the user (at most once a minute) that relay-only has no relay to use.
    fn notice_no_relay(&mut self, why: &str) {
        let now = Instant::now();
        if self
            .turn_notice_at
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(60))
        {
            return;
        }
        self.turn_notice_at = Some(now);
        self.emit(AppEvent::Notice(format!(
            "Your TURN server cannot be used ({why}). Relay-only is on, so no connection is \
             made without it; check the server in Settings."
        )));
    }

    fn schedule_retry(&mut self, peer: &str, was_initiator: bool) {
        if !self.is_contact(peer) {
            return;
        }
        let we_offer = was_initiator || should_initiate(&self.me, peer);
        let st = self.peer_mut(peer);
        if st.online == Some(false) || st.retry_armed {
            return;
        }
        if st.attempt >= RETRY_MAX_ATTEMPTS && st.online != Some(true) {
            tracing::info!(peer = %crate::short_id(peer), "giving up until presence says online");
            return;
        }
        let n = st.attempt.min(RETRY_MAX_ATTEMPTS);
        st.attempt += 1;
        st.retry_armed = true;
        let base = RETRY_BASE.saturating_mul(1 << n.min(10)).min(RETRY_MAX);
        let jitter = base.mul_f64(0.25 * rand::thread_rng().r#gen::<f64>());
        // The side that would not offer waits longer, so the initiator's retry usually wins.
        let extra = if we_offer {
            Duration::ZERO
        } else {
            OFFER_FALLBACK
        };
        self.after(
            base + jitter + extra,
            Timer::Retry {
                peer: peer.to_owned(),
            },
        );
    }

    fn on_timer(&mut self, t: Timer) {
        match t {
            Timer::Pace { peer, epoch } => self.on_pace(&peer, epoch),
            Timer::AnswerTimeout { peer, epoch } => {
                if self.conn_mut(&peer, epoch).is_some_and(|c| !c.remote_set) {
                    tracing::info!(peer = %crate::short_id(&peer), "no answer");
                    self.conn_failed(&peer, FailReason::Timeout);
                }
            }
            Timer::ConnectTimeout { peer, epoch } => {
                if self.conn_mut(&peer, epoch).is_some_and(|c| !c.is_open()) {
                    self.conn_failed(&peer, FailReason::Timeout);
                }
            }
            Timer::DisconnectGrace { peer, epoch } => {
                if self.conn_mut(&peer, epoch).is_some_and(|c| {
                    matches!(
                        c.last_state,
                        Some(RTCPeerConnectionState::Disconnected | RTCPeerConnectionState::Failed)
                    )
                }) {
                    self.conn_failed(&peer, FailReason::Timeout);
                }
            }
            Timer::CallRing { call_id } => {
                let ringing = self.calls.get(&call_id).is_some_and(|c| {
                    matches!(c.info.state, CallState::Outgoing | CallState::Incoming)
                });
                if ringing {
                    if self.calls[&call_id].info.incoming {
                        self.end_call(&call_id, CallEnd::NoAnswer);
                    } else {
                        self.signal_call_end(&call_id, false);
                        self.end_call(&call_id, CallEnd::NoAnswer);
                    }
                }
            }
            Timer::CallConnect { call_id } => {
                if self
                    .calls
                    .get(&call_id)
                    .is_some_and(|c| c.info.state == CallState::Connecting)
                {
                    self.signal_call_end(&call_id, false);
                    self.end_call(
                        &call_id,
                        CallEnd::Failed("the media connection did not come up".into()),
                    );
                }
            }
            Timer::RestartTimeout {
                peer,
                epoch,
                generation,
            } => {
                let Some(conn) = self.conn_mut(&peer, epoch) else {
                    return;
                };
                let Some(restart) = conn.restart.as_ref().filter(|r| r.generation == generation)
                else {
                    return;
                };
                let connected = conn.last_state == Some(RTCPeerConnectionState::Connected);
                match crate::wire::on_restart_expiry(connected, restart.answered) {
                    RestartExpiry::Done => conn.restart = None,
                    RestartExpiry::TakeBack => {
                        // The path works and the contact's app did not answer: the offer
                        // is taken back and the connection goes on as it was.
                        if let Some(h) = conn.handle.as_ref() {
                            let _ = h.rollback();
                        }
                        conn.restart = None;
                        conn.unsent = None;
                    }
                    RestartExpiry::Rebuild => {
                        tracing::info!(peer = %crate::short_id(&peer), "the ICE restart found no path; rebuilding");
                        self.conn_failed(&peer, FailReason::Timeout);
                    }
                }
            }
            Timer::CallReoffer {
                call_id,
                generation,
            } => {
                let Some(c) = self.calls.get_mut(&call_id) else {
                    return;
                };
                if c.reoffer != Some(generation) {
                    return;
                }
                tracing::info!(call = %call_id, "the call's reoffer was not answered; taking it back");
                c.reoffer = None;
                c.unsent = None;
                if let Some(h) = c.handle.as_ref() {
                    let _ = h.rollback();
                }
            }
            Timer::BindingTimeout { peer, epoch } => {
                if self.conn_mut(&peer, epoch).is_some_and(|c| !c.verified) {
                    tracing::info!(peer = %crate::short_id(&peer), "no channel binding; closing");
                    self.conn_failed(&peer, FailReason::Timeout);
                }
            }
            Timer::OfferFallback { peer } => {
                let st = self.peer_mut(&peer);
                st.fallback_armed = false;
                if st.conn.is_none() && st.online != Some(false) {
                    tracing::debug!(peer = %crate::short_id(&peer), "no offer came; offering ourselves");
                    self.schedule_offer(&peer);
                }
            }
            Timer::OfferSlot { peer } => {
                let st = self.peer_mut(&peer);
                st.offer_waiting = false;
                if st.conn.is_none() {
                    self.schedule_offer(&peer);
                }
            }
            Timer::Retry { peer } => {
                let st = self.peer_mut(&peer);
                st.retry_armed = false;
                if st.conn.is_none() && st.online != Some(false) {
                    self.connect(&peer, true);
                }
            }
            Timer::Probe => {
                self.probe_wake = None;
                self.run_probes();
            }
            Timer::TransferPump { peer } => self.pump_transfers(&peer),
            Timer::TransferOpen { id, epoch } => self.on_transfer_open_timeout(&id, epoch),
        }
    }

    fn mark_online(&mut self, peer: &str) {
        let st = self.peer_mut(peer);
        st.online = Some(true);
        st.offline_by_error = false;
        self.probes.clear(peer);
    }

    /// Offer again to the soft-offline contacts that are due (`reconnect`). Nothing goes out
    /// while the relay is away or has rate-limited us.
    fn run_probes(&mut self) {
        let now = Instant::now();
        if !self.registered || self.signaling_backoff_until.is_some_and(|t| now < t) {
            return;
        }
        let (state, peers) = (&self.state, &self.peers);
        let due = self.probes.take_due(
            now,
            |p| probe_active(state, peers, p),
            |p| probe_ready(peers, p),
            || rand::thread_rng().r#gen::<f64>(),
        );
        for peer in due {
            let soft = self
                .peers
                .get(&peer)
                .is_some_and(|st| st.online == Some(false) && st.offline_by_error);
            if !soft || !self.is_contact(&peer) {
                self.probes.clear(&peer);
                continue;
            }
            tracing::debug!(peer = %crate::short_id(&peer), "probing a contact the relay called offline");
            self.peer_mut(&peer).quiet_probe = true;
            self.connect(&peer, true);
        }
        self.arm_probe_wake();
    }

    /// Make sure a `Timer::Probe` fires when the next probe is due.
    fn arm_probe_wake(&mut self) {
        let now = Instant::now();
        let (state, peers) = (&self.state, &self.peers);
        let Some(at) = self.probes.next_wake(
            now,
            |p| probe_active(state, peers, p),
            |p| probe_ready(peers, p),
        ) else {
            return;
        };
        if self
            .probe_wake
            .is_some_and(|armed| armed > now && armed <= at)
        {
            return;
        }
        self.probe_wake = Some(at);
        self.after(
            at.saturating_duration_since(now)
                .max(Duration::from_millis(20)),
            Timer::Probe,
        );
    }

    fn on_tick(&mut self) {
        if self.pairing_until.is_some_and(|t| Instant::now() >= t) {
            self.close_pairing_code();
        }
        self.tick_pairings();
        self.expire_transfers();
        if !self.registered {
            return;
        }
        let candidates: Vec<String> = self
            .state
            .contacts
            .iter()
            .filter(|c| self.state.waits_for(&c.peer_id))
            .map(|c| c.peer_id.clone())
            .collect();
        for peer in candidates {
            let st = self.peer_mut(&peer);
            if st.conn.is_some() || st.retry_armed || st.offer_waiting || st.fallback_armed {
                continue;
            }
            if st.online.is_none() {
                self.connect(&peer, false);
            }
        }
        // Also the fallback for probes held back while the relay was away or rate-limiting.
        self.run_probes();
    }

    // ── Incoming content ──────────────────────────────────────────

    fn on_data(&mut self, peer: &str, payload: &[u8]) {
        match DcFrame::parse(payload) {
            DcFrame::Identity { peer_id, features } => {
                let ours = self.cfg.renegotiation;
                if let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.as_mut()) {
                    conn.peer_restarts = crate::wire::restarts(ours, &features);
                }
                if !peer_id.eq_ignore_ascii_case(peer) {
                    tracing::warn!(
                        peer = %crate::short_id(peer),
                        claimed = %crate::short_id(&peer_id),
                        "identity frame does not match the signaling peer"
                    );
                }
            }
            DcFrame::Envelope { hex: h } => match hex::decode(&h) {
                Ok(bytes) => self.on_envelope(peer, &bytes),
                Err(_) => tracing::debug!("non-hex envelope"),
            },
            DcFrame::Other => {}
        }
    }

    fn on_envelope(&mut self, peer: &str, bytes: &[u8]) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        let mut decoded = None;
        if self.client.has_session(&pid) {
            match decrypt_for_peer(self.client.sessions(), &pid, bytes) {
                Ok(d) => decoded = Some(d),
                Err(e) => tracing::debug!(peer = %crate::short_id(peer), %e, "decrypt failed"),
            }
        }
        if decoded.is_none()
            && self.pairing_open()
            && let Some(pb) = self.pending_bootstrap.as_ref()
            && let Some(ik) = bootstrap_ik(bytes)
            && PeerId::from_public_key(&ik) == pid
        {
            match try_bootstrap_and_decrypt(
                self.client.sessions(),
                bytes,
                &self.my_pk,
                &pb.seed,
                &pb.ratchet_secret,
            ) {
                // PNP-001 §5.3.1: the session is materialized; its first message is the
                // scanner's BootstrapHandshake (PNP-003 §5.4).
                Ok(d) => self.on_bootstrap_envelope(peer, ik, &d),
                Err(e) => tracing::info!(peer = %crate::short_id(peer), %e, "bootstrap failed"),
            }
            self.persist_sessions();
            return;
        }
        let Some(d) = decoded else {
            return;
        };
        // The responder of a PNP-002 handshake: this is the session's first message.
        if self
            .pairings
            .get(peer)
            .is_some_and(|slot| slot.pairing.state() == PairingState::Accepted)
        {
            self.on_first_session_message(peer);
        }
        // We may hold a session only now (the presenter, on the scanner's bootstrap
        // envelope): our binding can go out.
        if d.msg_type != msg_type::CHANNEL_BINDING {
            self.send_binding(peer);
        }
        if self.pairings.contains_key(peer)
            && !matches!(
                d.msg_type,
                msg_type::HANDSHAKE | msg_type::CHANNEL_BINDING | msg_type::SYSTEM
            )
        {
            tracing::debug!(peer = %crate::short_id(peer), "content before the pairing completed");
            self.persist_sessions();
            return;
        }
        match d.msg_type {
            msg_type::CHAT => {
                let text = String::from_utf8_lossy(&d.plaintext).into_owned();
                if !self.is_contact(peer) {
                    let (contact, _) = self.upsert_contact(peer, None);
                    self.emit(AppEvent::ContactAdded(contact));
                    self.send_watch();
                }
                let id = self.state.alloc_message_id();
                let msg = ChatMessage {
                    id,
                    peer_id: peer.to_owned(),
                    direction: Direction::Received,
                    text,
                    timestamp_ms: now_ms(),
                    state: DeliveryState::Received,
                };
                self.state.push_message(msg.clone());
                self.emit(AppEvent::Message(msg));
            }
            msg_type::SYSTEM => {}
            msg_type::HANDSHAKE => self.on_handshake(peer, &d.plaintext),
            msg_type::CHANNEL_BINDING => self.on_binding(peer, &d.plaintext),
            parolnet_transfer::MSG_TYPE_FILE_TRANSFER => {
                self.on_transfer_control(peer, &d.plaintext)
            }
            msg_type::CALL_SIGNAL => match CallSignal::parse(&d.plaintext) {
                Some(sig) => self.on_call_signal(peer, sig),
                None => tracing::debug!(peer = %crate::short_id(peer), "malformed call signal"),
            },
            other => {
                tracing::debug!(msg_type = other, "message type not handled in this slice");
            }
        }
        self.persist_sessions();
    }
}

// ── Calls ─────────────────────────────────────────────────────

impl Engine {
    fn emit_call(&self, call_id: &str) {
        if let Some(c) = self.calls.get(call_id) {
            self.emit(AppEvent::Call(c.info.clone()));
        }
    }

    fn set_call_state(&mut self, call_id: &str, state: CallState) {
        if let Some(c) = self.calls.get_mut(call_id)
            && c.info.state != state
        {
            c.info.state = state;
            self.emit_call(call_id);
        }
    }

    fn busy(&self) -> bool {
        self.calls.values().any(|c| !c.info.is_over())
    }

    fn new_call(&mut self, call_id: String, peer: &str, video: bool, incoming: bool) {
        let (frames_tx, frames_rx) = mpsc::unbounded_channel();
        let (media_tx, media_rx) = mpsc::channel(CALL_MEDIA_CAPACITY);
        let info = CallInfo {
            call_id: call_id.clone(),
            peer_id: peer.to_owned(),
            video,
            incoming,
            state: if incoming {
                CallState::Incoming
            } else {
                CallState::Outgoing
            },
            // As offered, until the descriptions say otherwise.
            local_video: video,
            remote_video: video,
            renegotiable: false,
        };
        self.calls.insert(
            call_id.clone(),
            Call {
                info,
                handle: None,
                remote_offer: None,
                remote_set: false,
                pending_ice: Vec::new(),
                frames_rx: Some(frames_rx),
                media: Some(CallMedia {
                    frames: FrameSink(frames_tx),
                    events: media_rx,
                }),
                media_tx,
                described: false,
                established: false,
                reoffer: None,
                unsent: None,
            },
        );
        self.after(CALL_RING_TIMEOUT, Timer::CallRing { call_id });
    }

    /// Send a call signal on the contact's verified data channel (never queued: a ring
    /// delivered hours later is wrong).
    fn send_call_signal(&mut self, peer: &str, sig: &CallSignal) -> bool {
        let Some(pid) = peer_id_of(peer) else {
            return false;
        };
        if !self
            .peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(Conn::is_verified)
        {
            return false;
        }
        let envelope = match encrypt_for_peer(
            self.client.sessions(),
            &pid,
            msg_type::CALL_SIGNAL,
            sig.to_json().as_bytes(),
            now_secs(),
            None,
        ) {
            Ok(e) => hex::encode(e),
            Err(e) => {
                tracing::warn!(%e, "call signal encrypt failed");
                return false;
            }
        };
        let ok = self.send_on_channel(peer, &envelope);
        self.persist_sessions();
        ok
    }

    fn start_call(&mut self, peer: &str, video: bool) -> Result<CallInfo, AppError> {
        if !self.is_contact(peer) {
            return Err(AppError::UnknownContact(peer.to_owned()));
        }
        // PNP-001-MUST-081: call signals only on a verified channel (and not before the
        // pairing's session is the final one).
        if self.pairings.contains_key(peer) {
            return Err(AppError::NotConnected(peer.to_owned()));
        }
        if !self
            .peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(Conn::is_verified)
        {
            self.connect(peer, true);
            return Err(AppError::NotConnected(peer.to_owned()));
        }
        if self.busy() {
            return Err(AppError::Busy);
        }
        let call_id = new_call_id();
        self.new_call(call_id.clone(), peer, video, false);
        self.spawn_call_conn(&call_id, true);
        self.emit_call(&call_id);
        Ok(self.calls[&call_id].info.clone())
    }

    fn accept_call(&mut self, call_id: &str) -> Result<CallInfo, AppError> {
        let Some(c) = self.calls.get(call_id) else {
            return Err(AppError::UnknownCall(call_id.to_owned()));
        };
        if c.info.state != CallState::Incoming {
            return Err(AppError::UnknownCall(call_id.to_owned()));
        }
        self.set_call_state(call_id, CallState::Connecting);
        self.spawn_call_conn(call_id, false);
        self.after(
            CALL_CONNECT_TIMEOUT,
            Timer::CallConnect {
                call_id: call_id.to_owned(),
            },
        );
        Ok(self.calls[call_id].info.clone())
    }

    fn reject_call(&mut self, call_id: &str) {
        if self
            .calls
            .get(call_id)
            .is_some_and(|c| c.info.state == CallState::Incoming)
        {
            self.signal_call_end(call_id, true);
            self.end_call(call_id, CallEnd::Declined);
        }
    }

    fn hangup_call(&mut self, call_id: &str) {
        let Some(c) = self.calls.get(call_id) else {
            return;
        };
        if c.info.is_over() {
            return;
        }
        if c.info.state == CallState::Incoming {
            self.reject_call(call_id);
            return;
        }
        self.signal_call_end(call_id, false);
        self.end_call(call_id, CallEnd::HungUp);
    }

    /// Tell the contact the call is over (`reject` for an unanswered incoming call).
    fn signal_call_end(&mut self, call_id: &str, reject: bool) {
        let Some(peer) = self.calls.get(call_id).map(|c| c.info.peer_id.clone()) else {
            return;
        };
        let sig = if reject {
            CallSignal::Reject {
                call_id: call_id.to_owned(),
            }
        } else {
            CallSignal::Hangup {
                call_id: call_id.to_owned(),
            }
        };
        if !self.send_call_signal(&peer, &sig) {
            tracing::debug!(call = %call_id, "call end not delivered (no verified channel)");
        }
    }

    fn end_call(&mut self, call_id: &str, why: CallEnd) {
        let Some(mut c) = self.calls.remove(call_id) else {
            return;
        };
        if c.info.is_over() {
            return;
        }
        c.info.state = CallState::Ended(why);
        tracing::info!(call = %call_id, state = ?c.info.state, "call over");
        self.emit(AppEvent::Call(c.info.clone()));
        if let Some(h) = c.handle.take() {
            tokio::spawn(h.close());
        }
    }

    fn spawn_call_conn(&mut self, call_id: &str, initiator: bool) {
        let Some(c) = self.calls.get_mut(call_id) else {
            return;
        };
        let video = c.info.video;
        // When `reoffer`s cross, the caller's stands and the callee yields (PNP-011).
        let polite = c.info.incoming;
        let frames_rx = c.frames_rx.take();
        let media_tx = c.media_tx.clone();
        let config = crate::call::connection_config(video, polite, self.rtc_base());
        let input = self.input.clone();
        let id = call_id.to_owned();
        tracing::info!(call = %call_id, initiator, video, "starting the call connection");
        tokio::spawn(async move {
            let (handle, mut events) = match parolnet_rtc::spawn(config).await {
                Ok(x) => x,
                Err(e) => {
                    let _ = input.send(Input::CallRtcReady {
                        call_id: id,
                        result: Err(e.into()),
                    });
                    return;
                }
            };
            if let Some(rx) = frames_rx {
                tokio::spawn(crate::call::pump_frames(rx, handle.frame_sender()));
            }
            if input
                .send(Input::CallRtcReady {
                    call_id: id.clone(),
                    result: Ok(handle),
                })
                .is_err()
            {
                return;
            }
            let mut kinds: HashMap<String, MediaKind> = HashMap::new();
            while let Some(event) = events.recv().await {
                match event {
                    RtcEvent::Track {
                        track_id,
                        kind,
                        mime_type,
                    } => {
                        let kind = match kind {
                            RtpCodecKind::Video => MediaKind::Video,
                            _ => MediaKind::Audio,
                        };
                        kinds.insert(track_id, kind);
                        let _ = media_tx.try_send(MediaEvent::Track { kind, mime_type });
                    }
                    RtcEvent::Rtp { track_id, packet } => {
                        if let Some(kind) = kinds.get(&track_id) {
                            let _ = media_tx.try_send(MediaEvent::Rtp {
                                kind: *kind,
                                packet,
                            });
                        }
                    }
                    RtcEvent::KeyframeRequested => {
                        let _ = media_tx.try_send(MediaEvent::KeyframeRequested);
                    }
                    RtcEvent::TargetBitrate { bps } => {
                        let _ = media_tx.try_send(MediaEvent::TargetBitrate { bps });
                    }
                    other => {
                        if input
                            .send(Input::CallRtc {
                                call_id: id.clone(),
                                event: other,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    }

    fn on_call_ready(&mut self, call_id: &str, result: Result<RtcHandle, StartFailure>) {
        let handle = match result {
            Ok(h) => h,
            Err(e) => {
                self.signal_call_end(call_id, false);
                self.end_call(call_id, CallEnd::Failed(e.message));
                return;
            }
        };
        let Some(c) = self.calls.get_mut(call_id) else {
            tokio::spawn(handle.close());
            return;
        };
        let ok = if !c.info.incoming {
            handle.create_offer().is_ok()
        } else if let Some(offer) = c.remote_offer.take() {
            match RTCSessionDescription::offer(offer) {
                Ok(desc) => {
                    let ok = handle.set_remote_description(desc).is_ok();
                    c.remote_set = ok;
                    for cand in c.pending_ice.drain(..) {
                        let _ = handle.add_remote_candidate(cand);
                    }
                    ok
                }
                Err(_) => false,
            }
        } else {
            false
        };
        c.handle = Some(handle);
        if !ok {
            self.signal_call_end(call_id, false);
            self.end_call(call_id, CallEnd::Failed("bad session description".into()));
        }
    }

    fn on_call_rtc(&mut self, call_id: &str, event: RtcEvent) {
        let Some(c) = self.calls.get(call_id) else {
            return;
        };
        let peer = c.info.peer_id.clone();
        let video = c.info.video;
        match event {
            RtcEvent::LocalDescription(desc) => {
                let first = !c.described;
                let incoming = c.info.incoming;
                let is_offer = desc.sdp_type == RTCSdpType::Offer;
                if !first && is_offer && !c.info.renegotiable {
                    // An offer the connection made by itself (SRTP re-keying, PNP-011 section
                    // 7.6) to a peer that does not renegotiate: never sent (PNP-011-MUST-020).
                    // The call goes on as it was set up.
                    tracing::info!(call = %call_id, "re-offer to a peer that does not renegotiate taken back");
                    if let Some(h) = c.handle.as_ref() {
                        let _ = h.rollback();
                    }
                    return;
                }
                let sig = match (first, is_offer) {
                    (true, false) => CallSignal::Answer {
                        call_id: call_id.to_owned(),
                        video,
                        sdp: desc.sdp.clone(),
                        features: local_features(self.cfg.renegotiation),
                    },
                    (true, true) => CallSignal::Offer {
                        call_id: call_id.to_owned(),
                        video,
                        sdp: desc.sdp.clone(),
                        features: local_features(self.cfg.renegotiation),
                    },
                    (false, true) => CallSignal::Reoffer {
                        call_id: call_id.to_owned(),
                        sdp: desc.sdp.clone(),
                    },
                    (false, false) => CallSignal::Reanswer {
                        call_id: call_id.to_owned(),
                        sdp: desc.sdp.clone(),
                    },
                };
                self.next_epoch += 1;
                let generation = self.next_epoch;
                if let Some(c) = self.calls.get_mut(call_id) {
                    c.described = true;
                    if first && incoming {
                        // Our answer is made: the call is set up on our side.
                        c.established = true;
                    }
                    if !first && is_offer {
                        c.reoffer = Some(generation);
                    }
                }
                if !first && is_offer {
                    self.after(
                        CALL_REOFFER_TIMEOUT,
                        Timer::CallReoffer {
                            call_id: call_id.to_owned(),
                            generation,
                        },
                    );
                }
                if !self.send_call_signal(&peer, &sig) {
                    if first {
                        self.end_call(
                            call_id,
                            CallEnd::Failed("no verified connection to the contact".into()),
                        );
                    } else if let Some(c) = self.calls.get_mut(call_id) {
                        // The data connection is being rebuilt: the signal goes out when
                        // it is verified again.
                        c.unsent = Some(sig);
                    }
                }
            }
            RtcEvent::ConnectionState(state) => match state {
                RTCPeerConnectionState::Connected => {
                    self.set_call_state(call_id, CallState::Active);
                }
                RTCPeerConnectionState::Disconnected => {
                    // The media path is gone: look for another before ICE gives up.
                    self.restart_call(call_id);
                }
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    self.signal_call_end(call_id, false);
                    self.end_call(
                        call_id,
                        CallEnd::Failed(format!("media connection {state}")),
                    );
                }
                _ => {}
            },
            RtcEvent::Closed { error } => {
                self.end_call(
                    call_id,
                    CallEnd::Failed(error.unwrap_or_else(|| "media connection closed".into())),
                );
            }
            RtcEvent::RemoteMedia {
                kind: MediaKind::Video,
                sending,
            } => {
                if let Some(c) = self.calls.get_mut(call_id) {
                    let _ = c.media_tx.try_send(MediaEvent::RemoteVideo { sending });
                    if c.info.remote_video != sending || (sending && !c.info.video) {
                        c.info.remote_video = sending;
                        c.info.video |= sending;
                        self.emit_call(call_id);
                    }
                }
            }
            RtcEvent::LocalMedia {
                kind: MediaKind::Video,
                sending,
            } => {
                if let Some(c) = self.calls.get_mut(call_id) {
                    let _ = c.media_tx.try_send(MediaEvent::LocalVideo { sending });
                    if c.info.local_video != sending || (sending && !c.info.video) {
                        c.info.local_video = sending;
                        c.info.video |= sending;
                        self.emit_call(call_id);
                    }
                }
            }
            RtcEvent::Quality(stats) => {
                if c.info.state == CallState::Active {
                    self.emit(AppEvent::CallQuality {
                        call_id: call_id.to_owned(),
                        quality: CallQuality::new(stats),
                    });
                }
            }
            _ => {}
        }
    }

    /// Restart ICE on a call's connection (the network changed, or its path is gone): only
    /// with a contact whose app renegotiates, once the call is set up, and not while another
    /// `reoffer` of ours is unanswered.
    fn restart_call(&mut self, call_id: &str) {
        let Some(c) = self.calls.get(call_id) else {
            return;
        };
        if c.info.is_over() || !c.established || !c.info.renegotiable || c.reoffer.is_some() {
            return;
        }
        if let Some(h) = c.handle.as_ref() {
            tracing::info!(call = %call_id, "restarting the call's ICE");
            let _ = h.restart_ice();
        }
    }

    /// Turn our video on or off in a call that is set up.
    fn set_call_video(&mut self, call_id: &str, enabled: bool) -> Result<VideoChange, AppError> {
        let Some(c) = self.calls.get(call_id) else {
            return Err(AppError::UnknownCall(call_id.to_owned()));
        };
        if c.info.is_over() || !c.established {
            return Err(AppError::UnknownCall(call_id.to_owned()));
        }
        // With a contact whose app does not renegotiate the call stays as it was set up: a
        // video call's stream stays (black is sent for a camera that is off), an audio call
        // stays audio.
        match crate::call::video_change(c.info.renegotiable, c.info.local_video, enabled) {
            None => Err(AppError::CannotRenegotiate),
            Some(VideoChange::Unchanged) => Ok(VideoChange::Unchanged),
            Some(VideoChange::Renegotiating) => {
                let Some(h) = c.handle.as_ref() else {
                    return Err(AppError::UnknownCall(call_id.to_owned()));
                };
                h.set_sending(MediaKind::Video, enabled)
                    .map_err(|_| AppError::UnknownCall(call_id.to_owned()))?;
                Ok(VideoChange::Renegotiating)
            }
        }
    }

    /// The contact's data connection is verified (again): send the call signals that had
    /// to wait for it.
    fn flush_call_signals(&mut self, peer: &str) {
        let waiting: Vec<(String, CallSignal)> = self
            .calls
            .iter_mut()
            .filter(|(_, c)| c.info.peer_id == peer)
            .filter_map(|(id, c)| Some((id.clone(), c.unsent.take()?)))
            .collect();
        for (call_id, sig) in waiting {
            if !self.send_call_signal(peer, &sig)
                && let Some(c) = self.calls.get_mut(&call_id)
            {
                c.unsent = Some(sig);
            }
        }
    }

    fn on_call_signal(&mut self, peer: &str, sig: CallSignal) {
        let call_id = sig.call_id().to_owned();
        let ours = self.cfg.renegotiation;
        if let Some(c) = self.calls.get(&call_id)
            && c.info.peer_id != peer
        {
            tracing::warn!(peer = %crate::short_id(peer), "call signal for someone else's call");
            return;
        }
        match sig {
            CallSignal::Offer {
                video,
                sdp,
                features,
                ..
            } => {
                match crate::call::on_offer(self.calls.contains_key(&call_id), self.busy()) {
                    OfferDecision::Duplicate => return,
                    OfferDecision::Busy => {
                        let _ = self.send_call_signal(peer, &CallSignal::Reject { call_id });
                        return;
                    }
                    OfferDecision::Ring => {}
                }
                self.new_call(call_id.clone(), peer, video, true);
                if let Some(c) = self.calls.get_mut(&call_id) {
                    c.remote_offer = Some(sdp);
                    c.info.renegotiable = crate::call::renegotiates(ours, &features);
                }
                self.emit_call(&call_id);
            }
            CallSignal::Reoffer { sdp, .. } => {
                let Some(c) = self.calls.get_mut(&call_id) else {
                    return;
                };
                // Only for a call that is set up, and only when we said we take them. When
                // it crosses a `reoffer` of ours the caller's stands: the caller drops the
                // callee's, the callee drops its own and answers (what it wanted is offered
                // again afterwards by the driver).
                match crate::call::on_reoffer(
                    ours,
                    c.established,
                    c.info.is_over(),
                    c.reoffer.is_some(),
                    c.info.incoming,
                ) {
                    ReofferDecision::Ignore => return,
                    ReofferDecision::KeepOurs => {
                        tracing::debug!(call = %call_id, "crossing reoffers; keeping ours");
                        return;
                    }
                    ReofferDecision::Yield => {
                        c.reoffer = None;
                        c.unsent = None;
                    }
                    ReofferDecision::Answer => {}
                }
                if let (Some(h), Ok(desc)) = (c.handle.as_ref(), RTCSessionDescription::offer(sdp))
                {
                    let _ = h.set_remote_description(desc);
                }
            }
            CallSignal::Reanswer { sdp, .. } => {
                let Some(c) = self.calls.get_mut(&call_id) else {
                    return;
                };
                if c.reoffer.is_none() || c.info.is_over() {
                    return; // nobody waits for it
                }
                if let (Some(h), Ok(desc)) = (c.handle.as_ref(), RTCSessionDescription::answer(sdp))
                    && h.set_remote_description(desc).is_ok()
                {
                    c.reoffer = None;
                }
            }
            CallSignal::Answer { sdp, features, .. } => {
                let Some(c) = self.calls.get_mut(&call_id) else {
                    return;
                };
                if c.info.incoming || c.remote_set {
                    return;
                }
                let applied = match (c.handle.as_ref(), RTCSessionDescription::answer(sdp)) {
                    (Some(h), Ok(desc)) => h.set_remote_description(desc).is_ok(),
                    _ => false,
                };
                if !applied {
                    self.signal_call_end(&call_id, false);
                    self.end_call(&call_id, CallEnd::Failed("bad answer".into()));
                    return;
                }
                c.remote_set = true;
                c.established = true;
                c.info.renegotiable = crate::call::renegotiates(ours, &features);
                if let Some(h) = c.handle.as_ref() {
                    for cand in c.pending_ice.drain(..) {
                        let _ = h.add_remote_candidate(cand);
                    }
                }
                self.set_call_state(&call_id, CallState::Connecting);
                self.after(CALL_CONNECT_TIMEOUT, Timer::CallConnect { call_id });
            }
            CallSignal::Ice { candidate, .. } => {
                let Some(c) = self.calls.get_mut(&call_id) else {
                    return;
                };
                if candidate.candidate.is_empty() {
                    return;
                }
                match (c.remote_set, c.handle.as_ref()) {
                    (true, Some(h)) => {
                        let _ = h.add_remote_candidate(candidate);
                    }
                    _ if c.pending_ice.len() < CALL_PENDING_ICE_MAX => {
                        c.pending_ice.push(candidate)
                    }
                    _ => {}
                }
            }
            CallSignal::Hangup { .. } => self.end_call(&call_id, CallEnd::RemoteHungUp),
            CallSignal::Reject { .. } => self.end_call(&call_id, CallEnd::Rejected),
        }
    }
}

/// The user waits for this contact: messages are queued for it, or they asked to connect.
fn probe_active(state: &State, peers: &HashMap<String, PeerState>, peer: &str) -> bool {
    state.waits_for(peer) || peers.get(peer).is_some_and(|st| st.wanted)
}

/// No connection attempt to this contact is under way or scheduled.
fn probe_ready(peers: &HashMap<String, PeerState>, peer: &str) -> bool {
    peers.get(peer).is_none_or(|st| {
        st.conn.is_none() && !st.retry_armed && !st.offer_waiting && !st.fallback_armed
    })
}

/// The scanner's identity key from a bootstrap envelope's cleartext `source_hint`
/// (PNP-001-MUST-063 packs the 32-byte Ed25519 key there).
fn bootstrap_ik(bytes: &[u8]) -> Option<[u8; 32]> {
    let env = CborCodec.decode(bytes).ok()?;
    env.cleartext_header.source_hint.map(|p| p.0)
}

/// Map message ids dropped from the queue back to their peers.
fn dropped_owners(state: &State, ids: Vec<u64>) -> Vec<(String, u64)> {
    ids.into_iter()
        .filter_map(|id| {
            state
                .messages
                .iter()
                .find(|(_, list)| list.iter().any(|m| m.id == id))
                .map(|(p, _)| (p.clone(), id))
        })
        .collect()
}
