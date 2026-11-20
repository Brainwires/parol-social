//! End-to-end tests of the relay binary's operating profiles.
//!
//! Each test starts its own `parolnet-relay` process on a free loopback port
//! with an isolated key directory, talks to it over real WebSockets and HTTP,
//! and kills it on drop. The default profile is signaling-only; tests that
//! need the relay profile pass `SIGNALING_ONLY=0`.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Relay {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn http_client() -> reqwest::Client {
    // reqwest is built without a bundled rustls provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    reqwest::Client::new()
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

impl Relay {
    /// Start a relay. Generous connection / identity budgets unless the
    /// test overrides them, since every client here shares 127.0.0.1.
    async fn start(envs: &[(&str, &str)]) -> Relay {
        let port = free_port();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "parolnet-relay-sig-test-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parolnet-relay"));
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RELAY_PORT", port.to_string())
            .env("RELAY_KEY_FILE", dir.join("relay.key"))
            .env("RELAY_AUTHORITY_KEY_FILE", dir.join("relay-authority.cbor"))
            .env("RUST_LOG", "warn")
            .env("RELAY_CONN_PER_MINUTE", "1000")
            .env("RELAY_MAX_PEERS_PER_IP", "16")
            .env("RELAY_MAX_CONNS_PER_IP", "32")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn relay binary");
        let relay = Relay { child, port, dir };
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return relay;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("relay did not start listening on {port}");
    }

    fn http(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    async fn ws(&self) -> Ws {
        let (ws, _) = connect_async(format!("ws://127.0.0.1:{}/ws", self.port))
            .await
            .expect("ws connect");
        ws
    }
}

struct Identity {
    key: ed25519_dalek::SigningKey,
    peer_id: String,
}

impl Identity {
    fn new() -> Identity {
        use sha2::{Digest, Sha256};
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let peer_id = hex::encode(Sha256::digest(key.verifying_key().to_bytes()));
        Identity { key, peer_id }
    }
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

/// Next JSON text frame, or `None` on close / timeout.
async fn recv(ws: &mut Ws, timeout_ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return Some(serde_json::from_str(&t).unwrap()),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

/// Next frame of `msg_type`, skipping others.
async fn recv_type(ws: &mut Ws, msg_type: &str, timeout_ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        let v = recv(ws, left.as_millis() as u64).await?;
        if v["type"] == msg_type {
            return Some(v);
        }
    }
}

/// True when the server closes the socket within `timeout_ms`.
async fn closed_within(ws: &mut Ws, timeout_ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return false,
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// Run the challenge-response registration; returns the `registered` frame
/// or the error frame.
async fn register(ws: &mut Ws, id: &Identity) -> Value {
    use ed25519_dalek::Signer;
    send(ws, json!({"type": "register", "peer_id": id.peer_id})).await;
    let ch = recv_type(ws, "challenge", 3000).await.expect("challenge");
    let nonce = hex::decode(ch["nonce"].as_str().unwrap()).unwrap();
    let sig = id.key.sign(&nonce);
    send(
        ws,
        json!({
            "type": "register",
            "peer_id": id.peer_id,
            "pubkey": hex::encode(id.key.verifying_key().to_bytes()),
            "signature": hex::encode(sig.to_bytes()),
            "nonce": hex::encode(&nonce),
        }),
    )
    .await;
    loop {
        let v = recv(ws, 3000).await.expect("register reply");
        if v["type"] == "registered" || v["type"] == "error" {
            return v;
        }
    }
}

async fn registered_peer(relay: &Relay) -> (Ws, Identity) {
    let id = Identity::new();
    let mut ws = relay.ws().await;
    let r = register(&mut ws, &id).await;
    assert_eq!(r["type"], "registered", "{r}");
    (ws, id)
}

#[tokio::test]
async fn registered_announces_signaling_only_profile_and_relays_sdp() {
    let relay = Relay::start(&[]).await;
    let (mut a, ida) = registered_peer(&relay).await;
    let (mut b, idb) = registered_peer(&relay).await;

    send(
        &mut a,
        json!({"type": "rtc_offer", "to": idb.peer_id, "payload": "v=0 offer"}),
    )
    .await;
    let got = recv_type(&mut b, "rtc_offer", 3000).await.expect("offer");
    assert_eq!(got["from"], ida.peer_id);
    assert_eq!(got["payload"], "v=0 offer");

    send(
        &mut b,
        json!({"type": "rtc_answer", "to": ida.peer_id, "payload": "v=0 answer"}),
    )
    .await;
    let got = recv_type(&mut a, "rtc_answer", 3000).await.expect("answer");
    assert_eq!(got["from"], idb.peer_id);

    // A fresh registration reports the profile.
    let mut c = relay.ws().await;
    let r = register(&mut c, &Identity::new()).await;
    assert_eq!(r["profile"], "signaling-only");
}

#[tokio::test]
async fn content_frames_are_refused() {
    let relay = Relay::start(&[]).await;
    let (mut a, _) = registered_peer(&relay).await;
    let (_b, idb) = registered_peer(&relay).await;
    for t in ["message", "gossip", "something_else"] {
        send(
            &mut a,
            json!({"type": t, "to": idb.peer_id, "payload": "00", "token": "00"}),
        )
        .await;
        let e = recv_type(&mut a, "error", 3000).await.expect("error");
        assert_eq!(e["code"], "signaling_only", "{t}: {e}");
    }
}

#[tokio::test]
async fn binary_frames_close_the_socket() {
    let relay = Relay::start(&[]).await;
    let (mut a, _) = registered_peer(&relay).await;
    a.send(Message::Binary(vec![0u8; 512].into()))
        .await
        .unwrap();
    assert!(
        closed_within(&mut a, 3000).await,
        "onion cell must close the socket"
    );
}

#[tokio::test]
async fn oversize_frames_close_the_socket() {
    let relay = Relay::start(&[]).await;
    let (mut a, idb) = registered_peer(&relay).await;
    let big = "x".repeat(33 * 1024);
    send(
        &mut a,
        json!({"type": "rtc_offer", "to": idb.peer_id, "payload": big}),
    )
    .await;
    assert!(closed_within(&mut a, 3000).await, "32 KiB frame cap");
}

#[tokio::test]
async fn signaling_payload_caps() {
    let relay = Relay::start(&[]).await;
    let (mut a, _) = registered_peer(&relay).await;
    let (mut b, idb) = registered_peer(&relay).await;
    send(
        &mut a,
        json!({"type": "rtc_offer", "to": idb.peer_id, "payload": "o".repeat(16 * 1024 + 1)}),
    )
    .await;
    let e = recv_type(&mut a, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "payload_too_large");
    send(
        &mut a,
        json!({"type": "rtc_ice", "to": idb.peer_id, "payload": "i".repeat(2 * 1024 + 1)}),
    )
    .await;
    let e = recv_type(&mut a, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "payload_too_large");
    // Nothing reached B.
    assert!(recv_type(&mut b, "rtc_offer", 300).await.is_none());
    assert!(recv_type(&mut b, "rtc_ice", 100).await.is_none());
}

#[tokio::test]
async fn signaling_to_offline_peer_is_never_queued() {
    let relay = Relay::start(&[]).await;
    let (mut a, _) = registered_peer(&relay).await;
    let offline = Identity::new();
    send(
        &mut a,
        json!({"type": "rtc_offer", "to": offline.peer_id, "payload": "x"}),
    )
    .await;
    let e = recv_type(&mut a, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "peer_offline");
    assert_eq!(e["peer_id"], offline.peer_id);
    // The peer comes online later and receives nothing.
    let mut late = relay.ws().await;
    assert_eq!(register(&mut late, &offline).await["type"], "registered");
    assert!(recv_type(&mut late, "rtc_offer", 500).await.is_none());
}

#[tokio::test]
async fn per_sender_signaling_rate_limit() {
    let relay = Relay::start(&[]).await;
    let (mut a, _) = registered_peer(&relay).await;
    let (_b, idb) = registered_peer(&relay).await;
    for _ in 0..61 {
        send(
            &mut a,
            json!({"type": "rtc_ice", "to": idb.peer_id, "payload": "c"}),
        )
        .await;
    }
    let e = recv_type(&mut a, "error", 3000)
        .await
        .expect("rate limit error");
    assert_eq!(e["code"], "rate_limited", "{e}");
}

#[tokio::test]
async fn unregistered_socket_may_only_register_and_is_closed_on_deadline() {
    let relay = Relay::start(&[("RELAY_REGISTER_TIMEOUT_SECS", "1")]).await;
    let (_b, idb) = registered_peer(&relay).await;
    let mut anon = relay.ws().await;
    send(
        &mut anon,
        json!({"type": "rtc_offer", "to": idb.peer_id, "payload": "x"}),
    )
    .await;
    let e = recv_type(&mut anon, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "not_registered");
    send(
        &mut anon,
        json!({"type": "watch", "peer_ids": [idb.peer_id]}),
    )
    .await;
    let e = recv_type(&mut anon, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "not_registered");
    // ping is allowed before registration
    send(&mut anon, json!({"type": "ping", "ts": 7})).await;
    let p = recv_type(&mut anon, "pong", 3000).await.unwrap();
    assert_eq!(p["ts"], 7);
    assert!(closed_within(&mut anon, 3000).await, "register deadline");
}

#[tokio::test]
async fn presence_push_is_mutual_only() {
    let relay = Relay::start(&[]).await;
    let (mut a, ida) = registered_peer(&relay).await;
    let (mut b, idb) = registered_peer(&relay).await;
    let (mut c, _idc) = registered_peer(&relay).await;

    // A watches B: not mutual, nobody hears anything.
    send(&mut a, json!({"type": "watch", "peer_ids": [idb.peer_id]})).await;
    assert!(recv_type(&mut a, "presence", 300).await.is_none());
    // B watches A: both learn the other is online.
    send(&mut b, json!({"type": "watch", "peer_ids": [ida.peer_id]})).await;
    let pb = recv_type(&mut b, "presence", 3000).await.unwrap();
    assert_eq!(pb["peer_id"], ida.peer_id);
    assert_eq!(pb["online"], true);
    let pa = recv_type(&mut a, "presence", 3000).await.unwrap();
    assert_eq!(pa["peer_id"], idb.peer_id);
    assert_eq!(pa["online"], true);

    // C, a stranger, watches A and learns nothing.
    send(&mut c, json!({"type": "watch", "peer_ids": [ida.peer_id]})).await;
    assert!(recv_type(&mut c, "presence", 300).await.is_none());

    // B leaves: A is told.
    b.close(None).await.unwrap();
    let gone = recv_type(&mut a, "presence", 3000).await.unwrap();
    assert_eq!(gone["peer_id"], idb.peer_id);
    assert_eq!(gone["online"], false);

    // B comes back on a new socket and re-watches: A hears it online again.
    let mut b2 = relay.ws().await;
    assert_eq!(register(&mut b2, &idb).await["type"], "registered");
    send(&mut b2, json!({"type": "watch", "peer_ids": [ida.peer_id]})).await;
    let back = recv_type(&mut a, "presence", 3000).await.unwrap();
    assert_eq!(back["online"], true);
    assert!(recv_type(&mut c, "presence", 200).await.is_none());
}

#[tokio::test]
async fn reconnect_overlap_keeps_the_newer_socket_routable() {
    let relay = Relay::start(&[]).await;
    let (mut a1, ida) = registered_peer(&relay).await;
    let mut a2 = relay.ws().await;
    assert_eq!(register(&mut a2, &ida).await["type"], "registered");
    // The older socket closes after the newer one registered.
    a1.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (mut b, _) = registered_peer(&relay).await;
    send(
        &mut b,
        json!({"type": "rtc_offer", "to": ida.peer_id, "payload": "still here"}),
    )
    .await;
    let got = recv_type(&mut a2, "rtc_offer", 3000)
        .await
        .expect("routed to newer socket");
    assert_eq!(got["payload"], "still here");
}

#[tokio::test]
async fn per_ip_connection_and_identity_caps() {
    let relay = Relay::start(&[
        ("RELAY_MAX_CONNS_PER_IP", "2"),
        ("RELAY_MAX_PEERS_PER_IP", "1"),
    ])
    .await;
    let mut s1 = relay.ws().await;
    let _s2 = relay.ws().await;
    let third = connect_async(format!("ws://127.0.0.1:{}/ws", relay.port)).await;
    assert!(
        third.is_err(),
        "third concurrent socket from one IP is refused"
    );

    assert_eq!(
        register(&mut s1, &Identity::new()).await["type"],
        "registered"
    );
    let mut s2 = _s2;
    let r = register(&mut s2, &Identity::new()).await;
    assert_eq!(r["code"], "too_many_peers", "{r}");

    // Closing a socket frees its slot.
    s1.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        connect_async(format!("ws://127.0.0.1:{}/ws", relay.port))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn relay_endpoints_are_absent_and_turn_is_never_minted() {
    let relay = Relay::start(&[
        ("TURN_SECRET", "would-be-secret"),
        ("TURN_DOMAIN", "turn.example"),
        ("STUN_URIS", "stun:stun.example:3478,turn:turn.example:3478"),
    ])
    .await;
    let (_a, _) = registered_peer(&relay).await;
    let http = http_client();
    for path in ["/tokens/issue", "/telemetry", "/endorse", "/directory/push"] {
        let r = http.post(relay.http(path)).body("x").send().await.unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    let r = http.get(relay.http("/federation/v1")).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let creds: Value = http
        .get(relay.http("/turn-credentials"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|t| serde_json::from_str(&t).unwrap())
        .unwrap();
    assert_eq!(creds["uris"], json!(["stun:stun.example:3478"]));
    assert_eq!(creds["credential"], "");
    assert_eq!(creds["profile"], "signaling-only");
    let boot: Value = http
        .get(relay.http("/bootstrap?exclude=x"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|t| serde_json::from_str(&t).unwrap())
        .unwrap();
    assert_eq!(boot, json!([]), "no online PeerIds for strangers");
    let r = http.get(relay.http("/directory")).send().await.unwrap();
    assert_eq!(r.status(), 200, "directory stays readable");
    assert!(
        !relay.dir.join("relay-authority.cbor").exists(),
        "no token authority state is written"
    );
}

// ---- relay profile: the default-build security fixes still apply ----------

#[tokio::test]
async fn relay_profile_requires_registration_for_content_frames() {
    let relay = Relay::start(&[("SIGNALING_ONLY", "0")]).await;
    let (_b, idb) = registered_peer(&relay).await;
    let mut anon = relay.ws().await;
    for t in ["message", "gossip"] {
        send(
            &mut anon,
            json!({"type": t, "to": idb.peer_id, "payload": "00", "token": "00"}),
        )
        .await;
        let e = recv_type(&mut anon, "error", 3000).await.unwrap();
        assert_eq!(e["code"], "not_registered", "{t}");
    }
    anon.send(Message::Binary(vec![0u8; 512].into()))
        .await
        .unwrap();
    let e = recv_type(&mut anon, "error", 3000).await.unwrap();
    assert_eq!(e["code"], "not_registered");
    let r = register(&mut anon, &Identity::new()).await;
    assert_eq!(r["profile"], "relay");
}

#[tokio::test]
async fn relay_profile_bounds_token_issuance() {
    let relay = Relay::start(&[("SIGNALING_ONLY", "0")]).await;
    let http = http_client();
    // Over-cap batch: 1025 elements (contents are irrelevant, the count is
    // checked before any element is parsed).
    #[derive(serde::Serialize)]
    struct Req {
        ed25519_pubkey_hex: String,
        ed25519_sig_hex: String,
        challenge_nonce_hex: String,
        blinded_bytes_list: Vec<serde_bytes::ByteBuf>,
    }
    let req = Req {
        ed25519_pubkey_hex: String::new(),
        ed25519_sig_hex: String::new(),
        challenge_nonce_hex: String::new(),
        blinded_bytes_list: vec![serde_bytes::ByteBuf::from(vec![0u8; 32]); 1025],
    };
    let mut body = Vec::new();
    ciborium::into_writer(&req, &mut body).unwrap();
    let r = http
        .post(relay.http("/tokens/issue"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    // Per-IP request budget: 10 per minute.
    let mut statuses = Vec::new();
    for _ in 0..12 {
        let r = http
            .post(relay.http("/tokens/issue"))
            .body("junk")
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    assert!(
        relay.dir.join("relay-authority.cbor").exists(),
        "relay profile keeps its token authority"
    );
}

#[tokio::test]
async fn relay_profile_frame_cap() {
    let relay = Relay::start(&[("SIGNALING_ONLY", "0")]).await;
    let (mut a, _) = registered_peer(&relay).await;
    let big = "x".repeat(129 * 1024);
    send(&mut a, json!({"type": "gossip", "payload": big})).await;
    assert!(closed_within(&mut a, 3000).await, "128 KiB frame cap");
}
