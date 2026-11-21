//! The core actor: one task owns the identity, sessions, contacts, store and every contact
//! connection. Commands from the client, relay frames from the signaling task, connection
//! events from `parolnet-rtc` tasks and timers all arrive as [`Input`]s.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parolnet_core::envelope::{decrypt_for_peer, encrypt_for_peer, try_bootstrap_and_decrypt};
use parolnet_core::{ParolNet, ParolNetConfig};
use parolnet_protocol::PeerId;
use parolnet_protocol::ProtocolCodec as _;
use parolnet_protocol::channel_binding::{BindingError, ChannelBinding};
use parolnet_protocol::codec::CborCodec;
use parolnet_rtc::rtc::peer_connection::sdp::RTCSessionDescription;
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtc::peer_connection::transport::RTCIceCandidateInit;
use parolnet_rtc::rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::{
    IcePolicy, MediaConfig, MediaKind, RtcConfig, RtcError, RtcEvent, RtcHandle, TurnServer,
};
use rand::Rng as _;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::call::{
    CallEnd, CallInfo, CallMedia, CallSignal, CallState, FrameSink, MediaEvent, OutFrame,
    new_call_id,
};
use crate::reconnect::ProbeSchedule;
use crate::signaling::{self, SigEvent, SigHandle, Signer};
use crate::store::{QueuedEnvelope, State, Store};
use crate::wire::{
    ClientFrame, DATA_CHANNEL_LABEL, DcFrame, SdpJson, ServerFrame, SignalKind, is_peer_id,
    msg_type, should_initiate,
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
const CALL_RING_TIMEOUT: Duration = Duration::from_secs(60);
/// From accepting (or the answer) to media flowing.
const CALL_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const CALL_PENDING_ICE_MAX: usize = 64;
/// Media events waiting for the client (RTP beyond this is dropped).
const CALL_MEDIA_CAPACITY: usize = 2048;

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
    Tick,
    CallRtcReady {
        call_id: String,
        result: Result<RtcHandle, StartFailure>,
    },
    CallRtc {
        call_id: String,
        event: RtcEvent,
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
    /// A soft-offline contact is due for a probe (see `reconnect`).
    Probe,
}

/// The presenter's half of a QR bootstrap (PNP-003), kept while its code is valid.
struct PendingBootstrap {
    seed: [u8; 32],
    ratchet_secret: [u8; 32],
}

impl Drop for PendingBootstrap {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.ratchet_secret.zeroize();
    }
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
}

impl Conn {
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
    stun: Vec<String>,
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
    let store = Store::open(&cfg.data_dir)?;
    let identity = store.load_or_create_identity()?;
    let my_pk = identity.public_key_bytes();
    let me = hex::encode(identity.peer_id());

    let mut secret = identity.secret_bytes();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.zeroize();
    let signer: Signer = Arc::new(move |nonce: &[u8]| {
        use ed25519_dalek::Signer as _;
        signing_key.sign(nonce).to_bytes()
    });

    let client = ParolNet::from_identity(ParolNetConfig::default(), identity);
    let state = store.load_state()?;
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

    let bind_ip = cfg
        .bind_ip
        .or_else(|| parolnet_rtc::default_local_ip(false))
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (events_tx, events_rx) = mpsc::unbounded_channel();

    let (sig_tx, mut sig_rx) = mpsc::unbounded_channel();
    let sig = signaling::spawn(
        cfg.relay_url.clone(),
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

    let reconnect = cfg.reconnect.clone();
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
        stun,
        bind_ip,
        next_epoch: 0,
        offer_history: VecDeque::new(),
        signaling_backoff_until: None,
        rate_limit_hits: 0,
        calls: HashMap::new(),
        probes: ProbeSchedule::new(reconnect, Instant::now()),
        probe_wake: None,
        turn_notice_at: None,
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
                    self.shutdown();
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
                Input::Tick => self.on_tick(),
                Input::CallRtcReady { call_id, result } => self.on_call_ready(&call_id, result),
                Input::CallRtc { call_id, event } => self.on_call_rtc(&call_id, event),
            }
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let calls: Vec<String> = self.calls.keys().cloned().collect();
        for id in calls {
            self.hangup_call(&id);
        }
        let peers: Vec<String> = self.peers.keys().cloned().collect();
        for p in peers {
            self.drop_conn(&p);
        }
        self.persist_sessions();
        self.sig.stop();
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
            Command::TurnSettings(reply) => {
                let _ = reply.send(self.state.turn.clone());
            }
            Command::SetTurnSettings(settings, reply) => {
                let _ = reply.send(self.set_turn(settings));
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
                })
                .collect(),
            pairing_open: self.pairing_open(),
            turn_configured: self.state.turn.is_some(),
            relay_only: self.state.turn.as_ref().is_some_and(|t| t.relay_only),
        }
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

    /// Store (or with `None` clear) the user's TURN server. It applies to every connection
    /// made from now on; data connections that exist are replaced at once so that turning
    /// relay-only on (or off) takes effect now. A contact in a call keeps its connections
    /// until the next reconnect.
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
        Ok(())
    }

    fn create_pairing_code(&mut self) -> Result<String, AppError> {
        let result = parolnet_core::bootstrap::generate_qr_payload_with_ratchet(&self.my_pk, None)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        self.pending_bootstrap = Some(PendingBootstrap {
            seed: result.seed,
            ratchet_secret: result.ratchet_secret,
        });
        self.pairing_until = Some(Instant::now() + self.cfg.pairing_window);
        Ok(hex::encode(&result.payload_bytes))
    }

    fn pair_with_code(&mut self, code: &str) -> Result<Contact, AppError> {
        let clean: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect();
        if clean.len() <= 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::InvalidCode(
                "expected the full pairing code (hex) from the contact's app".into(),
            ));
        }
        let bytes = hex::decode(&clean).map_err(|e| AppError::InvalidCode(e.to_string()))?;
        let (payload, bs) = self
            .client
            .process_qr(&bytes)
            .map_err(|e| AppError::InvalidCode(e.to_string()))?;
        let their_ik: [u8; 32] = payload
            .ik
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidCode("identity key must be 32 bytes".into()))?;
        if their_ik == self.my_pk {
            return Err(AppError::OwnCode);
        }
        let ratchet_key: [u8; 32] = payload
            .rk
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidCode("the code has no ratchet key".into()))?;
        let their_pid = PeerId::from_public_key(&their_ik);
        let peer = hex::encode(their_pid.0);
        self.client
            .establish_session(
                their_pid,
                parolnet_crypto::SharedSecret(bs),
                &ratchet_key,
                true,
            )
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        // PNP-001 §5.3.1 / MUST-063: the first envelope carries our identity key as
        // source_hint so the presenter can materialize its responder session.
        let bootstrap = encrypt_for_peer(
            self.client.sessions(),
            &their_pid,
            msg_type::SYSTEM,
            &[],
            now_secs(),
            Some(PeerId(self.my_pk)),
        )
        .map_err(|e| AppError::Crypto(e.to_string()))?;
        // A new session replaces whatever was queued under the old one.
        let stale = self.state.take_queue_for(&peer);
        for e in stale {
            if let Some(id) = e.message_id {
                self.mark_message(&peer, id, DeliveryState::Dropped);
            }
        }
        self.state.enqueue_front(QueuedEnvelope {
            peer_id: peer.clone(),
            envelope: hex::encode(bootstrap),
            created_ms: now_ms(),
            message_id: None,
        });
        let (contact, new) = self.upsert_contact(&peer, Some(hex::encode(their_ik)));
        self.emit(if new {
            AppEvent::ContactAdded(contact.clone())
        } else {
            AppEvent::ContactUpdated(contact.clone())
        });
        self.persist_sessions();
        self.send_watch();
        // The presenter does not know us yet, so it neither watches us nor offers: offer now.
        let st = self.peer_mut(&peer);
        st.online = None;
        st.offline_by_error = false;
        st.quiet_probe = false;
        st.attempt = 0;
        st.failures = 0;
        self.probes.clear(&peer);
        self.drop_conn(&peer);
        self.connect(&peer, true);
        Ok(contact)
    }

    fn send_text(&mut self, peer: &str, text: &str) -> Result<ChatMessage, AppError> {
        let pid = peer_id_of(peer).ok_or_else(|| AppError::UnknownContact(peer.to_owned()))?;
        if !self.client.has_session(&pid) {
            return Err(AppError::NoSession(peer.to_owned()));
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
        let mut msg = ChatMessage {
            id,
            peer_id: peer.to_owned(),
            direction: Direction::Sent,
            text: text.to_owned(),
            timestamp_ms: now_ms(),
            state: DeliveryState::Queued,
        };
        if self.send_on_channel(peer, &envelope) {
            msg.state = DeliveryState::Sent;
        } else {
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
            self.connect(peer, false);
            // A soft-offline contact is now waited for: its next probe may be due sooner.
            self.arm_probe_wake();
        }
        self.state.push_message(msg.clone());
        self.persist_sessions();
        self.emit(AppEvent::Message(msg.clone()));
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

    /// Send a content envelope on the contact's data channel once its binding has verified
    /// (PNP-001-SHOULD-018). False when there is no verified channel.
    fn send_on_channel(&mut self, peer: &str, envelope_hex: &str) -> bool {
        if !self
            .peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(Conn::is_verified)
        {
            return false;
        }
        self.send_raw(peer, envelope_hex)
    }

    /// Send an envelope on the open data channel, verified or not (the bootstrap envelope
    /// and our own binding).
    fn send_raw(&mut self, peer: &str, envelope_hex: &str) -> bool {
        let Some(conn) = self.peers.get(peer).and_then(|p| p.conn.as_ref()) else {
            return false;
        };
        let (Some(dc), Some(handle)) = (conn.dc, conn.handle.as_ref()) else {
            return false;
        };
        handle.send_text(dc, DcFrame::chat(envelope_hex)).is_ok()
    }

    /// Send the queued bootstrap-completing envelopes (no chat message; they lead the
    /// queue) before the binding: the presenter needs one to have a session at all.
    fn flush_bootstrap(&mut self, peer: &str) {
        let entries = self.state.take_queue_for(peer);
        let mut rest = Vec::new();
        let mut sent = false;
        for e in entries {
            if rest.is_empty() && e.message_id.is_none() && self.send_raw(peer, &e.envelope) {
                sent = true;
                continue;
            }
            rest.push(e);
        }
        for e in rest.into_iter().rev() {
            self.state.enqueue_front(e);
        }
        if sent {
            self.save();
        }
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
                self.set_path(peer, PathState::Direct);
                self.flush_queue(peer);
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

    fn flush_queue(&mut self, peer: &str) {
        let entries = self.state.take_queue_for(peer);
        if entries.is_empty() {
            return;
        }
        let mut rest = Vec::new();
        for e in entries {
            if !rest.is_empty() || !self.send_on_channel(peer, &e.envelope) {
                rest.push(e);
                continue;
            }
            if let Some(id) = e.message_id {
                self.mark_message(peer, id, DeliveryState::Sent);
            }
        }
        for e in rest.into_iter().rev() {
            self.state.enqueue_front(e);
        }
        self.save();
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
                    .filter(|c| self.state.queued_for(&c.peer_id) > 0)
                    .map(|c| c.peer_id.clone())
                    .collect();
                for p in waiting {
                    self.connect(&p, false);
                }
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
                if !conn.initiator || conn.remote_set {
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
        });
        st.fallback_armed = false;
        // A background probe of a contact believed offline shows nothing until it is answered.
        let quiet = std::mem::take(&mut st.quiet_probe) && st.online == Some(false);
        if !quiet && !matches!(st.path, PathState::NoDirectPath | PathState::BindingFailed) {
            self.set_path(peer, PathState::Connecting);
        }
        let (turn, ice_policy) = self.ice_setup();
        let config = RtcConfig {
            bind: SocketAddr::new(self.bind_ip, 0),
            stun_servers: self.stun.clone(),
            turn,
            ice_policy,
            data_channel: initiator.then(|| DATA_CHANNEL_LABEL.to_owned()),
            ..Default::default()
        };
        let input = self.input.clone();
        let peer_owned = peer.to_owned();
        tokio::spawn(async move {
            match parolnet_rtc::spawn(config).await {
                Ok((handle, mut events)) => {
                    let ready = Input::RtcReady {
                        peer: peer_owned.clone(),
                        epoch,
                        result: Ok(handle),
                    };
                    if input.send(ready).is_err() {
                        return;
                    }
                    while let Some(event) = events.recv().await {
                        let ev = Input::Rtc {
                            peer: peer_owned.clone(),
                            epoch,
                            event,
                        };
                        if input.send(ev).is_err() {
                            return;
                        }
                    }
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
        let Some(conn) = self.conn_mut(peer, epoch) else {
            return;
        };
        match event {
            RtcEvent::LocalDescription(desc) => {
                conn.local_sdp = Some(desc.sdp.clone());
                let initiator = conn.initiator;
                let payload = serde_json::to_string(&SdpJson {
                    sdp_type: if initiator { "offer" } else { "answer" }.to_owned(),
                    sdp: desc.sdp.clone(),
                })
                .unwrap_or_default();
                let kind = if initiator {
                    SignalKind::Offer
                } else {
                    SignalKind::Answer
                };
                if !self.signal(kind, peer, payload) {
                    tracing::debug!(peer = %crate::short_id(peer), "relay down; description not sent");
                    self.conn_failed(peer, FailReason::Error);
                    return;
                }
                if initiator {
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
                match state {
                    RTCPeerConnectionState::Disconnected => self.after(
                        DISCONNECT_GRACE,
                        Timer::DisconnectGrace {
                            peer: peer.to_owned(),
                            epoch,
                        },
                    ),
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
                if let Some(h) = conn.handle.as_ref() {
                    let _ = h.send_text(id, DcFrame::identity(&me));
                }
                self.mark_online(peer);
                tracing::info!(peer = %crate::short_id(peer), "data channel open; binding");
                // PNP-001 §10.5.1: the bootstrap-completing envelope first (we scanned the
                // peer's code), then our binding. Everything else waits for the peer's binding.
                self.flush_bootstrap(peer);
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
            RtcEvent::IceConnectionState(_)
            | RtcEvent::Track { .. }
            | RtcEvent::Rtp { .. }
            | RtcEvent::KeyframeRequested => {}
        }
    }

    fn drop_conn(&mut self, peer: &str) {
        if let Some(conn) = self.peers.get_mut(peer).and_then(|p| p.conn.take())
            && let Some(h) = conn.handle
        {
            tokio::spawn(h.close());
        }
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
            self.pairing_until = None;
            self.pending_bootstrap = None;
        }
        if !self.registered {
            return;
        }
        let candidates: Vec<String> = self
            .state
            .contacts
            .iter()
            .filter(|c| self.state.queued_for(&c.peer_id) > 0)
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
            DcFrame::Identity { peer_id } => {
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
        let mut bootstrapped_ik = None;
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
                Ok(d) => {
                    decoded = Some(d);
                    bootstrapped_ik = Some(ik);
                    self.pending_bootstrap = None;
                }
                Err(e) => tracing::info!(peer = %crate::short_id(peer), %e, "bootstrap failed"),
            }
        }
        let Some(d) = decoded else {
            return;
        };
        // We may hold a session only now (the presenter, on the scanner's bootstrap
        // envelope): our binding can go out.
        if d.msg_type != msg_type::CHANNEL_BINDING {
            self.send_binding(peer);
        }
        if let Some(ik) = bootstrapped_ik {
            let (contact, new) = self.upsert_contact(peer, Some(hex::encode(ik)));
            tracing::info!(peer = %crate::short_id(peer), "paired (presenter side)");
            self.emit(if new {
                AppEvent::ContactAdded(contact)
            } else {
                AppEvent::ContactUpdated(contact)
            });
            self.send_watch();
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
            msg_type::CHANNEL_BINDING => self.on_binding(peer, &d.plaintext),
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
        // PNP-001-MUST-081: call signals only on a verified channel.
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
        let frames_rx = c.frames_rx.take();
        let media_tx = c.media_tx.clone();
        let (turn, ice_policy) = self.ice_setup();
        let config = RtcConfig {
            bind: SocketAddr::new(self.bind_ip, 0),
            stun_servers: self.stun.clone(),
            turn,
            ice_policy,
            media: MediaConfig {
                recv_opus: true,
                send_opus: true,
                recv_vp8: video,
                send_vp8: video,
            },
            ..Default::default()
        };
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
                let sig = if c.info.incoming {
                    CallSignal::Answer {
                        call_id: call_id.to_owned(),
                        video,
                        sdp: desc.sdp.clone(),
                    }
                } else {
                    CallSignal::Offer {
                        call_id: call_id.to_owned(),
                        video,
                        sdp: desc.sdp.clone(),
                    }
                };
                if !self.send_call_signal(&peer, &sig) {
                    self.end_call(
                        call_id,
                        CallEnd::Failed("no verified connection to the contact".into()),
                    );
                }
            }
            RtcEvent::ConnectionState(state) => match state {
                RTCPeerConnectionState::Connected => {
                    self.set_call_state(call_id, CallState::Active);
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
            _ => {}
        }
    }

    fn on_call_signal(&mut self, peer: &str, sig: CallSignal) {
        let call_id = sig.call_id().to_owned();
        if let Some(c) = self.calls.get(&call_id)
            && c.info.peer_id != peer
        {
            tracing::warn!(peer = %crate::short_id(peer), "call signal for someone else's call");
            return;
        }
        match sig {
            CallSignal::Offer { video, sdp, .. } => {
                if self.calls.contains_key(&call_id) {
                    return; // a duplicate
                }
                if self.busy() {
                    let _ = self.send_call_signal(peer, &CallSignal::Reject { call_id });
                    return;
                }
                self.new_call(call_id.clone(), peer, video, true);
                if let Some(c) = self.calls.get_mut(&call_id) {
                    c.remote_offer = Some(sdp);
                }
                self.emit_call(&call_id);
            }
            CallSignal::Answer { sdp, .. } => {
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
    state.queued_for(peer) > 0 || peers.get(peer).is_some_and(|st| st.wanted)
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
