//! Black-box harness: the real relay binary, the real headless client (`parolnet-app`) and a
//! scripted peer.
//!
//! The scripted peer ([`RawPeer`]) speaks the same protocols as a client but does only what a
//! test tells it to: it registers on the relay, scans the app's pairing code, offers a
//! WebRTC connection through the relay and then sends, withholds or corrupts envelopes on the
//! data channel. What the app does in response is observed from outside: its events and what
//! arrives on the channel.
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
use parolnet_core::envelope::{DecryptedEnvelope, decrypt_from_envelope, encrypt_into_envelope};
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
        let dir = unique_dir("app");
        let mut cfg = AppConfig::new(dir.join("data"), relay.ws_url());
        cfg.stun_servers = Some(Vec::new());
        cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
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
    /// The Double Ratchet session of the pairing (we are its initiator).
    pub session: DoubleRatchetSession,
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
        let qr = parolnet_core::bootstrap::parse_qr_payload(&hex::decode(code).unwrap())
            .expect("pairing code");
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

    /// The bootstrap-completing envelope (PNP-001 §5.3.1): our identity key as source hint.
    pub fn send_bootstrap(&mut self) {
        let hint = Some(PeerId(self.id.public));
        let env = self.seal(0x03, &[], hint);
        self.send_bytes(&env);
    }

    /// The binding a conforming peer sends for this connection (PNP-001 §10.5.1).
    pub fn binding(&self) -> parolnet_protocol::channel_binding::ChannelBinding {
        parolnet_protocol::channel_binding::ChannelBinding::from_sdps(
            &self.local_sdp,
            &self.remote_sdp,
        )
        .unwrap()
    }

    /// Envelopes the app sends within `window`, decrypted (identity frames are skipped).
    /// Stops early once `until` holds for a received envelope.
    pub async fn receive(
        &mut self,
        window: Duration,
        mut until: impl FnMut(&DecryptedEnvelope) -> bool,
    ) -> Vec<DecryptedEnvelope> {
        let deadline = tokio::time::Instant::now() + window;
        let mut out = Vec::new();
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
            let bytes = hex::decode(v["payload"].as_str().unwrap()).unwrap();
            let d = decrypt_from_envelope(&mut self.session, &bytes)
                .expect("an envelope from the app decrypts under the pairing session");
            let stop = until(&d);
            out.push(d);
            if stop {
                break;
            }
        }
        out
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
