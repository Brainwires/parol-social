//! Black-box harness: the real relay binary, the real headless client (`parolnet-app`) and a
//! scripted peer.
//!
//! The scripted peer ([`RawPeer`]) speaks the same protocols as a client but does only what a
//! test tells it to: it registers on the relay, scans the app's pairing code (or shows one
//! for the app to scan), builds a WebRTC connection through the relay and then sends,
//! withholds or corrupts envelopes on the data channel. What the app does in response is
//! observed from outside: its events and what arrives on the channel.
//!
//! Pairing is PNP-003's exchange: [`RawPeer::send_bootstrap`] sends the BootstrapHandshake
//! and [`RawPeer::receive`] first carries the pairing through to the PNP-002 session, the
//! way a client does, before it hands envelopes to the test. A test that wants to play the
//! pairing by hand uses [`RawPeer::next_envelope`] and [`RawPeer::apply`] instead.
//!
//! The relay binary is `PAROLNET_RELAY_BIN` when set, else `parolnet-relay` in this test's
//! target directory (built with `cargo build -p parolnet-relay-server` on demand, as
//! `crates/parolnet-app/tests/two_peers.rs` does).

#![allow(dead_code)]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::Signer as _;
use futures_util::{SinkExt as _, StreamExt as _};
use parolnet_app::{AppConfig, AppEvent, AppHandle, RelayState};
use parolnet_core::bootstrap::NonceTracker;
use parolnet_core::bootstrap::pairing::{
    BootstrapKey, MSG_TYPE_HANDSHAKE, Pairing, PairingOutput, PairingState, Sas,
};
use parolnet_core::envelope::{DecryptedEnvelope, decrypt_from_envelope, encrypt_into_envelope};
use parolnet_crypto::IdentityKeyPair;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_protocol::address::PeerId;
use parolnet_rtc::rtc::peer_connection::sdp::RTCSessionDescription;
use parolnet_rtc::{RtcConfig, RtcEvent, RtcHandle};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tokio_tungstenite::tungstenite::Message;

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "parolnet-conformance-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAROLNET_RELAY_BIN") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/<test>-xxxx → target/<profile>/parolnet-relay
    let profile_dir = exe.parent().and_then(Path::parent).unwrap().to_owned();
    let bin = profile_dir.join(format!("parolnet-relay{}", std::env::consts::EXE_SUFFIX));
    // One build at a time, whichever test of this binary gets here first.
    static BUILD: Mutex<()> = Mutex::new(());
    let _guard = BUILD.lock().unwrap_or_else(|e| e.into_inner());
    if !bin.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "-p",
            "parolnet-relay-server",
            "--bin",
            "parolnet-relay",
        ]);
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("run cargo build for the relay");
        assert!(status.success(), "building parolnet-relay failed");
    }
    assert!(bin.exists(), "relay binary not found at {}", bin.display());
    bin
}

/// A relay process in its default configuration (signaling-only), plus `envs`.
pub struct Relay {
    child: Child,
    pub port: u16,
    dir: PathBuf,
    /// Everything the relay wrote to stdout and stderr so far.
    log: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Relay {
    pub async fn start(envs: &[(&str, &str)]) -> Relay {
        // The port is picked before the relay binds it, so another process can take it in
        // between; a relay that exits or never listens is started again on another port.
        for _ in 0..4 {
            if let Some(relay) = Relay::try_start(envs).await {
                return relay;
            }
        }
        panic!("the relay did not start");
    }

    async fn try_start(envs: &[(&str, &str)]) -> Option<Relay> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = unique_dir("relay");
        let mut cmd = Command::new(relay_binary());
        // No RUST_LOG: the relay logs at its default level.
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RELAY_PORT", port.to_string())
            .env("RELAY_KEY_FILE", dir.join("relay.key"))
            .env("RELAY_AUTHORITY_KEY_FILE", dir.join("relay-authority.cbor"))
            // Every client shares 127.0.0.1 here.
            .env("RELAY_CONN_PER_MINUTE", "1000")
            .env("RELAY_MAX_PEERS_PER_IP", "16")
            .env("RELAY_MAX_CONNS_PER_IP", "32")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn relay");
        let log = Arc::new(Mutex::new(Vec::new()));
        let pipes: [Box<dyn std::io::Read + Send>; 2] = [
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for mut pipe in pipes {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    log.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }
        let mut relay = Relay {
            child,
            port,
            dir,
            log,
        };
        for _ in 0..800 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return Some(relay);
            }
            if relay.child.try_wait().ok().flatten().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        None
    }

    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/ws", self.port)
    }

    pub async fn ws(&self) -> Ws {
        tokio_tungstenite::connect_async(self.ws_url())
            .await
            .expect("ws connect")
            .0
    }

    /// The relay's log output so far.
    pub fn log(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }

    /// `GET path` over plain HTTP/1.1: status code and body.
    pub async fn http_get(&self, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            self.port
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut raw)).await;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let body = if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            // Good enough for the small JSON answers read here: drop the chunk-size lines.
            body.lines()
                .filter(|l| !l.is_empty() && !l.bytes().all(|b| b.is_ascii_hexdigit()))
                .collect::<Vec<_>>()
                .join("")
        } else {
            body.to_owned()
        };
        (status, body)
    }
}

pub async fn ws_send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

/// Next JSON text frame, or `None` on close / timeout.
pub async fn ws_recv(ws: &mut Ws, timeout: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(&t).ok(),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

/// Next frame of `msg_type`, skipping others.
pub async fn ws_recv_type(ws: &mut Ws, msg_type: &str, timeout: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        let v = ws_recv(ws, left).await?;
        if v["type"] == msg_type {
            return Some(v);
        }
    }
}

/// An Ed25519 identity and its PeerId.
pub struct Identity {
    pub key: ed25519_dalek::SigningKey,
    pub public: [u8; 32],
    pub peer_id: String,
}

impl Identity {
    /// The same key as the crypto crate's identity type.
    pub fn keypair(&self) -> IdentityKeyPair {
        IdentityKeyPair::from_secret_bytes(&self.key.to_bytes())
    }

    pub fn new() -> Identity {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public = key.verifying_key().to_bytes();
        let peer_id = hex::encode(Sha256::digest(public));
        Identity {
            key,
            public,
            peer_id,
        }
    }
}

/// Challenge-response registration; returns the `registered` (or `error`) frame.
pub async fn register(ws: &mut Ws, id: &Identity) -> Value {
    ws_send(ws, json!({"type": "register", "peer_id": id.peer_id})).await;
    let ch = ws_recv_type(ws, "challenge", Duration::from_secs(5))
        .await
        .expect("challenge");
    let nonce = hex::decode(ch["nonce"].as_str().unwrap()).unwrap();
    let sig = id.key.sign(&nonce);
    ws_send(
        ws,
        json!({
            "type": "register",
            "peer_id": id.peer_id,
            "pubkey": hex::encode(id.public),
            "signature": hex::encode(sig.to_bytes()),
            "nonce": hex::encode(&nonce),
        }),
    )
    .await;
    loop {
        let v = ws_recv(ws, Duration::from_secs(5))
            .await
            .expect("register reply");
        if v["type"] == "registered" || v["type"] == "error" {
            return v;
        }
    }
}

// ── The real client ───────────────────────────────────────────

pub struct App {
    pub handle: AppHandle,
    pub events: UnboundedReceiver<AppEvent>,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl App {
    /// A fresh client on loopback, registered on `relay`.
    pub async fn start(relay: &Relay) -> App {
        App::start_with(relay, |_| {}).await
    }

    /// Where the client keeps its files.
    pub fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    /// [`App::start`] with the configuration adjusted by `configure`.
    pub async fn start_with(relay: &Relay, configure: impl FnOnce(&mut AppConfig)) -> App {
        let dir = unique_dir("app");
        let mut cfg = AppConfig::new(dir.join("data"), relay.ws_url());
        cfg.stun_servers = Some(Vec::new());
        cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
        // No user to compare verification codes, unless a test plays one.
        cfg.request_sas = false;
        configure(&mut cfg);
        let (handle, events) = parolnet_app::start(cfg).await.expect("start app");
        let mut app = App {
            handle,
            events,
            dir,
        };
        app.wait("registered", 20, |e| {
            matches!(e, AppEvent::Relay(RelayState::Registered { .. }))
        })
        .await;
        app
    }

    /// The next event matching `pred`; every event skipped on the way is handed to `seen`.
    pub async fn wait_seeing(
        &mut self,
        what: &str,
        secs: u64,
        mut pred: impl FnMut(&AppEvent) -> bool,
        mut seen: impl FnMut(&AppEvent),
    ) -> AppEvent {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Some(ev)) => {
                    seen(&ev);
                    if pred(&ev) {
                        return ev;
                    }
                }
                Ok(None) => panic!("event channel closed while waiting for {what}"),
                Err(_) => panic!("timed out after {secs}s waiting for {what}"),
            }
        }
    }

    pub async fn wait(
        &mut self,
        what: &str,
        secs: u64,
        pred: impl FnMut(&AppEvent) -> bool,
    ) -> AppEvent {
        self.wait_seeing(what, secs, pred, |_| {}).await
    }

    /// Every event that arrives within `window`.
    pub async fn drain(&mut self, window: Duration) -> Vec<AppEvent> {
        let deadline = tokio::time::Instant::now() + window;
        let mut out = Vec::new();
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, self.events.recv()).await {
            out.push(ev);
        }
        out
    }
}

// ── The scripted peer ─────────────────────────────────────────

/// A peer that scanned the app's pairing code and holds the open data channel to it.
pub struct RawPeer {
    pub id: Identity,
    pub app_peer: PeerId,
    /// The Double Ratchet session with the app: the bootstrap session of PNP-001 §5.3.1
    /// first, the PNP-002 session once the pairing is through.
    pub session: DoubleRatchetSession,
    /// The app's identity key and the Bootstrap Secret of the pairing.
    pub app_ik: [u8; 32],
    pub bs: [u8; 32],
    /// The pairing under way, if any.
    pub pairing: Option<Pairing>,
    pub nonces: NonceTracker,
    /// The SAS the pairing asked us to show, and whether it ended SAS-verified.
    pub sas: Option<Sas>,
    pub sas_verified: Option<bool>,
    /// Envelopes of the app read while the pairing was carried through.
    backlog: std::collections::VecDeque<DecryptedEnvelope>,
    pub ws: Ws,
    pub rtc: Option<RtcHandle>,
    pub events: Receiver<RtcEvent>,
    pub channel: usize,
    /// Our offer and the app's answer, as each crossed the relay.
    pub local_sdp: String,
    pub remote_sdp: String,
    pub opened_at: tokio::time::Instant,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl RawPeer {
    /// Scan `code` (the app's pairing code), register on the relay, offer a connection to
    /// the app and wait for the data channel. Nothing is sent on the channel yet.
    pub async fn connect(relay: &Relay, code: &str) -> RawPeer {
        let id = Identity::new();
        let qr = parolnet_core::bootstrap::parse_qr_text(code).expect("pairing code");
        let app_ik: [u8; 32] = qr.ik.as_slice().try_into().unwrap();
        let seed: [u8; 32] = qr.seed.as_slice().try_into().unwrap();
        let rk: [u8; 32] = qr.rk.as_slice().try_into().unwrap();
        let app_peer = PeerId::from_public_key(&app_ik);
        let bs =
            parolnet_core::bootstrap::derive_bootstrap_secret(&seed, &id.public, &app_ik).unwrap();
        let session = DoubleRatchetSession::initialize_initiator(bs, &rk).unwrap();

        let mut ws = relay.ws().await;
        let r = register(&mut ws, &id).await;
        assert_eq!(r["type"], "registered", "{r}");

        let link = Link::offer(&mut ws, &id, &hex::encode(app_peer.0)).await;
        RawPeer {
            id,
            app_peer,
            session,
            app_ik,
            bs,
            pairing: None,
            nonces: NonceTracker::default(),
            sas: None,
            sas_verified: None,
            backlog: Default::default(),
            ws,
            rtc: Some(link.rtc),
            events: link.events,
            channel: link.channel,
            local_sdp: link.local_sdp,
            remote_sdp: link.remote_sdp,
            opened_at: link.opened_at,
        }
    }

    /// Close our end of the connection; the relay registration stays.
    pub async fn disconnect(&mut self) {
        if let Some(rtc) = self.rtc.take() {
            rtc.close().await;
        }
    }

    /// Offer the app a new connection (same identity, same session) and wait for its channel.
    pub async fn reconnect(&mut self) {
        self.disconnect().await;
        let app_hex = hex::encode(self.app_peer.0);
        // Clients agree on who offers: the smaller PeerId (`should_initiate`). The app knows
        // us by now, so when that is the app we answer its offer instead of sending ours.
        let link = if parolnet_app::wire::should_initiate(&app_hex, &self.id.peer_id) {
            Link::answer(&mut self.ws, &app_hex).await
        } else {
            Link::offer(&mut self.ws, &self.id, &app_hex).await
        };
        self.rtc = Some(link.rtc);
        self.events = link.events;
        self.channel = link.channel;
        self.local_sdp = link.local_sdp;
        self.remote_sdp = link.remote_sdp;
        self.opened_at = link.opened_at;
    }

    /// An envelope for the app under our session, as wire bytes.
    pub fn seal(&mut self, msg_type: u8, body: &[u8], source_hint: Option<PeerId>) -> Vec<u8> {
        encrypt_into_envelope(
            &mut self.session,
            &self.app_peer,
            msg_type,
            body,
            now_secs(),
            source_hint,
        )
        .unwrap()
    }

    /// Put wire bytes on the data channel the way clients frame envelopes.
    pub fn send_bytes(&self, envelope: &[u8]) {
        self.rtc
            .as_ref()
            .expect("connected")
            .send_text(
                self.channel,
                json!({"type": "chat", "payload": hex::encode(envelope)}).to_string(),
            )
            .unwrap();
    }

    pub fn send(&mut self, msg_type: u8, body: &[u8]) {
        let env = self.seal(msg_type, body, None);
        self.send_bytes(&env);
    }

    /// The bootstrap-completing envelope (PNP-001 §5.3.1): our identity key as source hint,
    /// our BootstrapHandshake (PNP-003 §5.4) as its content. [`RawPeer::receive`] carries
    /// the pairing on from here.
    pub fn send_bootstrap(&mut self) {
        self.send_bootstrap_requesting_sas(false);
    }

    pub fn send_bootstrap_requesting_sas(&mut self, request_sas: bool) {
        let mut bs = self.bs;
        let (pairing, init) = Pairing::initiate(
            &self.id.keypair(),
            &mut bs,
            self.app_ik,
            request_sas,
            now_secs() * 1000,
        )
        .unwrap();
        self.pairing = Some(pairing);
        self.send_bootstrap_payload(&init);
    }

    /// A bootstrap-completing envelope with `payload` as its content.
    pub fn send_bootstrap_payload(&mut self, payload: &[u8]) {
        let hint = Some(PeerId(self.id.public));
        let env = self.seal(MSG_TYPE_HANDSHAKE, payload, hint);
        self.send_bytes(&env);
    }

    /// Do what a pairing step asks for: send its messages, switch to its session, send the
    /// new session's first message.
    pub fn apply(&mut self, outputs: Vec<PairingOutput>) {
        for output in outputs {
            match output {
                PairingOutput::Send(payload) => self.send(MSG_TYPE_HANDSHAKE, &payload),
                PairingOutput::ShowSas(sas) => self.sas = Some(sas),
                PairingOutput::Session(session) => self.session = *session,
                PairingOutput::Established { sas_verified } => {
                    self.sas_verified = Some(sas_verified);
                    if self.pairing.as_ref().is_some_and(|p| {
                        p.role() == parolnet_core::bootstrap::pairing::Role::Initiator
                    }) {
                        self.send(0x03, &[]);
                    }
                    self.pairing = None;
                }
            }
        }
    }

    /// Feed a handshake message of the app to our pairing.
    pub fn on_handshake(&mut self, payload: &[u8]) {
        let Some(pairing) = self.pairing.as_mut() else {
            return;
        };
        let outputs = pairing
            .on_message(payload, &mut self.nonces, now_secs() * 1000)
            .expect("the app's handshake message is valid");
        self.apply(outputs);
    }

    /// Whether our pairing still has protocol steps to take without a user (it is not
    /// waiting for our SAS confirmation).
    fn pairing_running(&self) -> bool {
        self.pairing.as_ref().is_some_and(|p| {
            p.state() != PairingState::SasPending || p.awaiting_peer_confirmation()
        })
    }

    /// The next envelope the app sends within `window`, as wire bytes.
    pub async fn next_raw(&mut self, window: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, self.events.recv()).await {
            let RtcEvent::DataChannelMessage { payload, .. } = ev else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(&payload) else {
                continue;
            };
            if v["type"] != "chat" {
                continue;
            }
            return Some(hex::decode(v["payload"].as_str().unwrap()).unwrap());
        }
        None
    }

    /// The next envelope the app sends within `window`, decrypted, whatever its type.
    pub async fn next_envelope(&mut self, window: Duration) -> Option<DecryptedEnvelope> {
        let bytes = self.next_raw(window).await?;
        Some(
            decrypt_from_envelope(&mut self.session, &bytes)
                .expect("an envelope from the app decrypts under the session"),
        )
    }

    /// Carry the pairing through: answer the app's handshake messages until the PNP-002
    /// session is established (or the pairing waits for a user). Other envelopes read on
    /// the way are kept for [`RawPeer::receive`].
    pub async fn complete_pairing(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while self.pairing_running() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let d = self
                .next_envelope(left)
                .await
                .expect("the app carries the pairing on");
            if d.msg_type == MSG_TYPE_HANDSHAKE {
                self.on_handshake(&d.plaintext);
            } else {
                self.backlog.push_back(d);
            }
        }
    }

    /// The binding a conforming peer sends for this connection (PNP-001 §10.5.1).
    pub fn binding(&self) -> parolnet_protocol::channel_binding::ChannelBinding {
        parolnet_protocol::channel_binding::ChannelBinding::from_sdps(
            &self.local_sdp,
            &self.remote_sdp,
        )
        .unwrap()
    }

    /// Envelopes the app sends within `window`, decrypted (identity frames are skipped, and
    /// so are the handshake messages of a pairing under way, which are answered).
    /// Stops early once `until` holds for a received envelope.
    pub async fn receive(
        &mut self,
        window: Duration,
        mut until: impl FnMut(&DecryptedEnvelope) -> bool,
    ) -> Vec<DecryptedEnvelope> {
        let deadline = tokio::time::Instant::now() + window;
        self.complete_pairing().await;
        let mut out = Vec::new();
        loop {
            let d = match self.backlog.pop_front() {
                Some(d) => d,
                None => {
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    match self.next_envelope(left).await {
                        Some(d) => d,
                        None => break,
                    }
                }
            };
            if d.msg_type == MSG_TYPE_HANDSHAKE && self.pairing.is_some() {
                self.on_handshake(&d.plaintext);
                continue;
            }
            let stop = until(&d);
            out.push(d);
            if stop {
                break;
            }
        }
        out
    }

    /// The app scans a code of ours: register, show `app` the code, answer its offer and
    /// read its bootstrap-completing envelope. Returns the peer (holding the bootstrap
    /// session, no pairing yet), the seed of the code and the app's BootstrapHandshake.
    pub async fn presented(relay: &Relay, app: &App) -> (RawPeer, [u8; 32], DecryptedEnvelope) {
        use parolnet_protocol::ProtocolCodec as _;
        let id = Identity::new();
        let qr =
            parolnet_core::bootstrap::generate_qr_payload_with_ratchet(&id.public, None).unwrap();
        let mut ws = relay.ws().await;
        let r = register(&mut ws, &id).await;
        assert_eq!(r["type"], "registered", "{r}");
        app.handle
            .pair_with_code(&qr.text)
            .await
            .expect("the app takes our code");
        let app_hex = app.handle.peer_id().to_owned();
        let app_ik: [u8; 32] = hex::decode(app.handle.public_key())
            .unwrap()
            .try_into()
            .unwrap();
        let mut link = Link::answer(&mut ws, &app_hex).await;
        // The app's first envelope: its identity key as source hint.
        let bytes = loop {
            let ev = next_rtc(&mut link.events, 20).await;
            let RtcEvent::DataChannelMessage { payload, .. } = ev else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(&payload) else {
                continue;
            };
            if v["type"] == "chat" {
                break hex::decode(v["payload"].as_str().unwrap()).unwrap();
            }
        };
        let envelope = parolnet_protocol::codec::CborCodec.decode(&bytes).unwrap();
        assert_eq!(
            envelope.cleartext_header.source_hint,
            Some(PeerId(app_ik)),
            "PNP-001-MUST-063: the scanner's first envelope carries its identity key"
        );
        let bs = parolnet_core::bootstrap::derive_bootstrap_secret(&qr.seed, &id.public, &app_ik)
            .unwrap();
        let mut session = DoubleRatchetSession::initialize_responder(
            bs,
            x25519_dalek::StaticSecret::from(qr.ratchet_secret),
        )
        .unwrap();
        let first = decrypt_from_envelope(&mut session, &bytes)
            .expect("the app's bootstrap envelope decrypts under the code's session");
        let peer = RawPeer {
            id,
            app_peer: PeerId::from_public_key(&app_ik),
            session,
            app_ik,
            bs,
            pairing: None,
            nonces: NonceTracker::default(),
            sas: None,
            sas_verified: None,
            backlog: Default::default(),
            ws,
            rtc: Some(link.rtc),
            events: link.events,
            channel: link.channel,
            local_sdp: link.local_sdp,
            remote_sdp: link.remote_sdp,
            opened_at: link.opened_at,
        };
        (peer, qr.seed, first)
    }

    /// Answer the app's BootstrapHandshake `init` as the presenter of the code with `seed`.
    pub fn respond(&mut self, seed: &[u8; 32], init: &[u8], request_sas: bool) {
        let (pairing, outputs) = Pairing::respond(
            &self.id.keypair(),
            &BootstrapKey::Seed(seed),
            init,
            Some(&self.app_ik),
            &mut self.nonces,
            request_sas,
            now_secs() * 1000,
        )
        .expect("the app's BootstrapHandshake verifies");
        self.pairing = Some(pairing);
        self.apply(outputs);
    }

    /// The presenter's last step: the next envelope of the app is the first message of the
    /// PNP-002 session.
    pub async fn expect_first_message(&mut self) -> DecryptedEnvelope {
        let d = self
            .next_envelope(Duration::from_secs(20))
            .await
            .expect("the app sends the session's first message");
        if let Some(pairing) = self.pairing.as_mut() {
            let outputs = pairing.on_first_message();
            self.apply(outputs);
        }
        d
    }
}

/// One WebRTC connection to the app with its `parolnet` data channel open.
struct Link {
    rtc: RtcHandle,
    events: Receiver<RtcEvent>,
    channel: usize,
    local_sdp: String,
    remote_sdp: String,
    opened_at: tokio::time::Instant,
}

impl Link {
    /// Offer through the relay, apply the app's answer, wait for the channel and send the
    /// identity frame clients open it with.
    async fn offer(ws: &mut Ws, id: &Identity, app_hex: &str) -> Link {
        let (rtc, mut events) = parolnet_rtc::spawn(RtcConfig {
            data_channel: Some("parolnet".into()),
            mdns: false,
            ..Default::default()
        })
        .await
        .expect("rtc");
        rtc.create_offer().unwrap();
        let local_sdp = loop {
            match next_rtc(&mut events, 20).await {
                RtcEvent::LocalDescription(d) => break d.sdp.clone(),
                _ => continue,
            }
        };
        ws_send(
            ws,
            json!({
                "type": "rtc_offer",
                "to": app_hex,
                "payload": json!({"type": "offer", "sdp": local_sdp}).to_string(),
            }),
        )
        .await;
        let answer = ws_recv_type(ws, "rtc_answer", Duration::from_secs(20))
            .await
            .expect("the app answers an offer while its pairing code is open");
        assert_eq!(answer["from"], app_hex);
        let payload: Value = serde_json::from_str(answer["payload"].as_str().unwrap()).unwrap();
        let remote_sdp = payload["sdp"].as_str().unwrap().to_owned();
        rtc.set_remote_description(RTCSessionDescription::answer(remote_sdp.clone()).unwrap())
            .unwrap();
        let channel = loop {
            match next_rtc(&mut events, 30).await {
                RtcEvent::DataChannelOpen { id, .. } => break id,
                _ => continue,
            }
        };
        let opened_at = tokio::time::Instant::now();
        rtc.send_text(
            channel,
            json!({"type": "identity", "peerId": id.peer_id}).to_string(),
        )
        .unwrap();
        Link {
            rtc,
            events,
            channel,
            local_sdp,
            remote_sdp,
            opened_at,
        }
    }
}

impl Link {
    /// Answer the app's next offer. Offers it made while we were away have timed out on its
    /// side, so an answer that opens no channel is followed by the next offer.
    async fn answer(ws: &mut Ws, app_hex: &str) -> Link {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let offer = ws_recv_type(ws, "rtc_offer", left)
                .await
                .expect("the app offers a connection to a contact it has messages for");
            if offer["from"] != app_hex {
                continue;
            }
            let payload: Value = serde_json::from_str(offer["payload"].as_str().unwrap()).unwrap();
            let remote_sdp = payload["sdp"].as_str().unwrap().to_owned();
            let (rtc, mut events) = parolnet_rtc::spawn(RtcConfig {
                mdns: false,
                ..Default::default()
            })
            .await
            .expect("rtc");
            rtc.set_remote_description(RTCSessionDescription::offer(remote_sdp.clone()).unwrap())
                .unwrap();
            let mut local_sdp = None;
            let mut channel = None;
            let opened = tokio::time::timeout(Duration::from_secs(12), async {
                while let Some(ev) = events.recv().await {
                    match ev {
                        RtcEvent::LocalDescription(d) => {
                            ws_send(
                                ws,
                                json!({
                                    "type": "rtc_answer",
                                    "to": app_hex,
                                    "payload": json!({"type": "answer", "sdp": d.sdp}).to_string(),
                                }),
                            )
                            .await;
                            local_sdp = Some(d.sdp.clone());
                        }
                        RtcEvent::DataChannelOpen { id, .. } => {
                            channel = Some(id);
                            break;
                        }
                        _ => {}
                    }
                }
            })
            .await;
            let (Ok(()), Some(local_sdp), Some(channel)) = (opened, local_sdp, channel) else {
                rtc.close().await;
                continue;
            };
            return Link {
                rtc,
                events,
                channel,
                local_sdp,
                remote_sdp,
                opened_at: tokio::time::Instant::now(),
            };
        }
    }
}

async fn next_rtc(events: &mut Receiver<RtcEvent>, secs: u64) -> RtcEvent {
    tokio::time::timeout(Duration::from_secs(secs), events.recv())
        .await
        .expect("timed out waiting for the connection")
        .expect("connection task ended")
}
