//! Two `parolnet-app` instances against a real relay binary in its default signaling-only
//! profile: QR-code pairing, encrypted chat both ways over the direct data channel, and the
//! sender-side queue across a restart (presence push brings the contact back); reconnecting
//! to a contact the relay called offline when no presence push ever comes; and chat and a
//! call relayed through the user's own TURN server (an in-process one here).
//!
//! The relay binary is `PAROLNET_RELAY_BIN` when set, else `parolnet-relay` next to this
//! test's target directory (brought up to date with `cargo build -p parolnet-relay-server`
//! once per test binary). It binds a port of its own choosing and reports it on stdout.

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use parolnet_app::{
    AppConfig, AppEvent, AppHandle, DeliveryState, Direction, PairingMark, PathState, RelayState,
    TurnSettings,
};
use parolnet_rtc::test_turn::TestTurnServer;
use tokio::sync::mpsc::UnboundedReceiver;

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

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("parolnet-app-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAROLNET_RELAY_BIN") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/two_peers-xxxx → target/<profile>/parolnet-relay
    let profile_dir = exe.parent().and_then(Path::parent).unwrap().to_owned();
    let bin = profile_dir.join(format!("parolnet-relay{}", std::env::consts::EXE_SUFFIX));
    // Built once per test binary and always through cargo: a relay binary that is merely
    // there may be older than the sources (one from before the listening line never
    // reports), and cargo does nothing when it is current.
    static BUILD: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
    let mut built = BUILD.lock().unwrap_or_else(|e| e.into_inner());
    if !*built {
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
        *built = true;
    }
    assert!(bin.exists(), "relay binary not found at {}", bin.display());
    bin
}

/// The port a relay started with `RELAY_PORT=0` bound, from the
/// `PAROLNET_RELAY_LISTENING=<addr>` line it prints on stdout once it serves. The rest of its
/// stdout is read and dropped so the relay never blocks on a full pipe.
async fn listening_port(stdout: ChildStdout) -> u16 {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        let mut out = std::io::BufReader::new(stdout);
        let mut line = Vec::new();
        while out.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            let text = String::from_utf8_lossy(&line);
            if let Some(addr) = text.trim_end().strip_prefix("PAROLNET_RELAY_LISTENING=")
                && let Some(tx) = tx.take()
            {
                let _ = tx.send(addr.to_owned());
            }
            line.clear();
        }
    });
    let addr = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("the relay did not report its listening address within 30 s")
        .expect("the relay exited before it reported its listening address");
    addr.parse::<std::net::SocketAddr>()
        .unwrap_or_else(|e| panic!("listening address {addr:?}: {e}"))
        .port()
}

/// A relay on a port it bound itself (`RELAY_PORT=0`): a port picked here and bound later
/// by the relay could be taken in between by another test's relay.
async fn start_relay() -> Relay {
    let dir = unique_dir("relay");
    let mut child = Command::new(relay_binary())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RELAY_PORT", "0")
        .env("RELAY_KEY_FILE", dir.join("relay.key"))
        .env("RELAY_AUTHORITY_KEY_FILE", dir.join("relay-authority.cbor"))
        .env("RUST_LOG", "warn")
        // Every client shares 127.0.0.1 here.
        .env("RELAY_CONN_PER_MINUTE", "1000")
        .env("RELAY_MAX_PEERS_PER_IP", "16")
        .env("RELAY_MAX_CONNS_PER_IP", "32")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay");
    let stdout = child.stdout.take().unwrap();
    // Built before the wait so that a relay that never reports is killed.
    let mut relay = Relay {
        child,
        port: 0,
        dir,
    };
    relay.port = listening_port(stdout).await;
    relay
}

fn config(dir: &Path, relay: &Relay, name: &str) -> AppConfig {
    let mut cfg = AppConfig::new(dir.join(name), format!("ws://127.0.0.1:{}/ws", relay.port));
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
    // No user here to compare verification codes.
    cfg.request_sas = false;
    cfg
}

/// Wait for an event matching `pred`, skipping others.
async fn wait_for(
    rx: &mut UnboundedReceiver<AppEvent>,
    what: &str,
    secs: u64,
    mut pred: impl FnMut(&AppEvent) -> bool,
) -> AppEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(ev)) => {
                if pred(&ev) {
                    return ev;
                }
            }
            Ok(None) => panic!("event channel closed while waiting for {what}"),
            Err(_) => panic!("timed out after {secs}s waiting for {what}"),
        }
    }
}

async fn registered(rx: &mut UnboundedReceiver<AppEvent>) {
    let ev = wait_for(rx, "registered", 20, |e| {
        matches!(e, AppEvent::Relay(RelayState::Registered { .. }))
    })
    .await;
    assert_eq!(
        ev,
        AppEvent::Relay(RelayState::Registered {
            profile: "signaling-only".into()
        })
    );
}

async fn received(rx: &mut UnboundedReceiver<AppEvent>, from: &str, text: &str) {
    let ev = wait_for(
        rx,
        &format!("message {text:?}"),
        30,
        |e| matches!(e, AppEvent::Message(m) if m.direction == Direction::Received),
    )
    .await;
    let AppEvent::Message(m) = ev else {
        unreachable!()
    };
    assert_eq!(m.peer_id, from);
    assert_eq!(m.text, text);
}

async fn start(cfg: AppConfig) -> (AppHandle, UnboundedReceiver<AppEvent>) {
    parolnet_app::start(cfg).await.expect("start app")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_chat_and_queue_across_restart() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let relay = start_relay().await;
    let dir = unique_dir("apps");

    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;

    // Alice presents a code (QR on screen); Bob enters it.
    let code = alice.create_pairing_code().await.unwrap();
    let contact = bob.pair_with_code(&code).await.unwrap();
    assert_eq!(contact.peer_id, alice.peer_id());
    assert_eq!(contact.identity_key.as_deref(), Some(alice.public_key()));
    assert!(matches!(
        bob.pair_with_code(&bob_code_of(&bob).await).await,
        Err(parolnet_app::AppError::OwnCode)
    ));

    // Bob's bootstrap envelope reaches Alice over the data channel: she now has him.
    let ev = wait_for(&mut alice_rx, "contact added on the presenter", 30, |e| {
        matches!(e, AppEvent::ContactAdded(_))
    })
    .await;
    let AppEvent::ContactAdded(c) = ev else {
        unreachable!()
    };
    assert_eq!(c.peer_id, bob.peer_id());
    assert_eq!(c.identity_key.as_deref(), Some(bob.public_key()));
    wait_for(&mut bob_rx, "direct path on the scanner", 30, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Direct,
                ..
            }
        )
    })
    .await;

    // Chat both ways over the direct data channel.
    let sent = bob
        .send_text(alice.peer_id(), "hello from bob")
        .await
        .unwrap();
    // A message waits for its send slot (PNP-006 §4.2): `Sent` follows as an event.
    assert_eq!(sent.state, DeliveryState::Queued);
    received(&mut alice_rx, bob.peer_id(), "hello from bob").await;
    let reply = alice
        .send_text(bob.peer_id(), "hi bob, alice here")
        .await
        .unwrap();
    assert_eq!(reply.state, DeliveryState::Queued);
    received(&mut bob_rx, alice.peer_id(), "hi bob, alice here").await;
    for i in 0..5 {
        bob.send_text(alice.peer_id(), &format!("burst {i}"))
            .await
            .unwrap();
    }
    for i in 0..5 {
        received(&mut alice_rx, bob.peer_id(), &format!("burst {i}")).await;
    }

    // A message leaves Bob's queue when Alice's end has acknowledged it, a moment after it
    // arrived: wait for that, so that what is queued below is the one new message.
    let emptied = tokio::time::Instant::now() + Duration::from_secs(10);
    while bob.snapshot().await.unwrap().contacts[0].queued != 0 {
        assert!(
            tokio::time::Instant::now() < emptied,
            "delivered messages were never acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Alice goes away. Bob's message waits on his device.
    alice.shutdown().await;
    drop(alice_rx);
    wait_for(&mut bob_rx, "alice offline", 30, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Offline,
                ..
            }
        )
    })
    .await;
    let queued = bob
        .send_text(contact.peer_id.as_str(), "are you there?")
        .await
        .unwrap();
    assert_eq!(queued.state, DeliveryState::Queued);
    let snap = bob.snapshot().await.unwrap();
    assert_eq!(snap.contacts.len(), 1);
    assert_eq!(snap.contacts[0].queued, 1);

    // Alice comes back with the same data directory: identity, contact and ratchet session
    // were persisted; presence push tells Bob, the queue flushes.
    let (alice2, mut alice2_rx) = start(config(&dir, &relay, "alice")).await;
    assert_eq!(alice2.peer_id(), contact.peer_id);
    registered(&mut alice2_rx).await;
    received(&mut alice2_rx, bob.peer_id(), "are you there?").await;
    wait_for(&mut bob_rx, "queued message sent", 30, |e| {
        matches!(e, AppEvent::MessageState { id, state: DeliveryState::Sent, .. } if *id == queued.id)
    })
    .await;
    alice2.send_text(bob.peer_id(), "back again").await.unwrap();
    received(&mut bob_rx, alice2.peer_id(), "back again").await;

    let history = alice2.messages(bob.peer_id()).await.unwrap();
    let texts: Vec<&str> = history.iter().map(|m| m.text.as_str()).collect();
    assert!(texts.contains(&"hello from bob"), "{texts:?}");
    assert!(texts.contains(&"are you there?"), "{texts:?}");

    alice2.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offers_from_strangers_are_ignored() {
    let relay = start_relay().await;
    let dir = unique_dir("strangers");
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let (eve, mut eve_rx) = start(config(&dir, &relay, "eve")).await;
    registered(&mut alice_rx).await;
    registered(&mut eve_rx).await;

    // Eve knows Alice's peer id (it is no secret) and forces an offer. Alice is not
    // pairing and does not know Eve: she must not answer (answering shows her IP address).
    eve.connect(alice.peer_id());
    let saw_contact = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match alice_rx.recv().await {
                Some(AppEvent::ContactAdded(_)) | Some(AppEvent::Path { .. }) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(!saw_contact, "alice reacted to a stranger's offer");
    let snap = alice.snapshot().await.unwrap();
    assert!(snap.contacts.is_empty());

    alice.shutdown().await;
    eve.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pairing lives in memory only. If the app is closed in the middle of one (here: while
/// the verification code waits for an answer), the next start removes the contact the
/// pairing had added and its bootstrap session; the other side's pairing ends with the
/// connection (PNP-003 §4), and its contact goes too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_in_the_middle_of_a_pairing_leaves_no_contact() {
    let relay = start_relay().await;
    let dir = unique_dir("pairing-restart");
    // Alice asks for the verification code, so both show it and neither goes on without it.
    let alice_cfg = || {
        let mut cfg = config(&dir, &relay, "alice");
        cfg.request_sas = true;
        cfg
    };
    let (alice, mut alice_rx) = start(alice_cfg()).await;
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;

    let code = alice.create_pairing_code().await.unwrap();
    let contact = bob.pair_with_code(&code).await.unwrap();
    assert_eq!(contact.pairing, Some(PairingMark::New));
    assert!(!contact.sas_verified);
    let is_sas = |e: &AppEvent| matches!(e, AppEvent::SasVerification { .. });
    wait_for(&mut bob_rx, "bob's verification code", 60, is_sas).await;
    wait_for(&mut alice_rx, "alice's verification code", 60, is_sas).await;
    let marks = |snap: parolnet_app::Snapshot| -> Vec<Option<PairingMark>> {
        snap.contacts.iter().map(|c| c.contact.pairing).collect()
    };
    assert_eq!(
        marks(bob.snapshot().await.unwrap()),
        [Some(PairingMark::New)]
    );
    assert_eq!(
        marks(alice.snapshot().await.unwrap()),
        [Some(PairingMark::New)]
    );

    // Bob's app is closed and started again: nothing of the pairing is left.
    bob.shutdown().await;
    drop(bob_rx);
    let (bob2, mut bob2_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut bob2_rx).await;
    assert!(bob2.snapshot().await.unwrap().contacts.is_empty());
    // Nor the bootstrap session that had been stored for it.
    assert!(matches!(
        bob2.send_text(alice.peer_id(), "to nobody").await,
        Err(parolnet_app::AppError::NoSession(_))
    ));

    // Alice's pairing ended with the connection it was on.
    wait_for(&mut alice_rx, "alice's pairing to fail", 90, |e| {
        matches!(e, AppEvent::PairingFailed { .. })
    })
    .await;
    assert!(alice.snapshot().await.unwrap().contacts.is_empty());

    // The other way round: a new pairing, and this time the presenter is restarted.
    let code = alice.create_pairing_code().await.unwrap();
    bob2.pair_with_code(&code).await.unwrap();
    wait_for(&mut alice_rx, "alice's verification code", 60, is_sas).await;
    alice.shutdown().await;
    drop(alice_rx);
    let (alice2, mut alice2_rx) = start(alice_cfg()).await;
    registered(&mut alice2_rx).await;
    let snap = alice2.snapshot().await.unwrap();
    assert!(snap.contacts.is_empty());
    // The code that was used did not come back either.
    assert!(snap.pairing_code.is_none());
    wait_for(&mut bob2_rx, "bob's pairing to fail", 90, |e| {
        matches!(e, AppEvent::PairingFailed { .. })
    })
    .await;
    assert!(bob2.snapshot().await.unwrap().contacts.is_empty());

    alice2.shutdown().await;
    bob2.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A code made by `app` itself (to check that pairing with one's own code is refused).
async fn bob_code_of(app: &AppHandle) -> String {
    app.create_pairing_code().await.unwrap()
}

/// Pair two fresh apps and wait for the verified direct path on both sides.
async fn paired_pair(
    relay: &Relay,
    dir: &Path,
) -> (
    (AppHandle, UnboundedReceiver<AppEvent>),
    (AppHandle, UnboundedReceiver<AppEvent>),
) {
    let (alice, mut alice_rx) = start(config(dir, relay, "alice")).await;
    let (bob, mut bob_rx) = start(config(dir, relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    for rx in [&mut alice_rx, &mut bob_rx] {
        wait_for(rx, "verified direct path", 30, |e| {
            matches!(
                e,
                AppEvent::Path {
                    state: PathState::Direct,
                    ..
                }
            )
        })
        .await;
    }
    ((alice, alice_rx), (bob, bob_rx))
}

async fn call_state(
    rx: &mut UnboundedReceiver<AppEvent>,
    what: &str,
    mut pred: impl FnMut(&parolnet_app::CallInfo) -> bool,
) -> parolnet_app::CallInfo {
    let ev = wait_for(rx, what, 30, |e| matches!(e, AppEvent::Call(c) if pred(c))).await;
    let AppEvent::Call(c) = ev else {
        unreachable!()
    };
    c
}

/// Feed opaque frames into a call and count the contact's RTP per kind until both kinds
/// reach `want`.
async fn exchange_media(media: parolnet_app::CallMedia, want: usize) -> (usize, usize) {
    use parolnet_app::{MediaEvent, MediaKind};
    let parolnet_app::CallMedia { frames, mut events } = media;
    let feeder = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tick.tick().await;
            if !frames.send(MediaKind::Audio, vec![0xf8; 60], 960)
                || !frames.send(MediaKind::Video, vec![0x10; 3000], 1800)
            {
                break;
            }
        }
    });
    let (mut audio, mut video) = (0, 0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while audio < want || video < want {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(MediaEvent::Rtp { kind, .. })) => match kind {
                MediaKind::Audio => audio += 1,
                MediaKind::Video => video += 1,
            },
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    feeder.abort();
    (audio, video)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn video_call_both_ways_then_hang_up() {
    let relay = start_relay().await;
    let dir = unique_dir("call");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir).await;

    let call = alice.start_call(bob.peer_id(), true).await.unwrap();
    assert_eq!(call.state, parolnet_app::CallState::Outgoing);
    assert!(matches!(
        alice.start_call(bob.peer_id(), false).await,
        Err(parolnet_app::AppError::Busy)
    ));
    let alice_media = alice.take_call_media(&call.call_id).await.unwrap();

    let ring = call_state(&mut bob_rx, "incoming call", |c| {
        c.state == parolnet_app::CallState::Incoming
    })
    .await;
    assert_eq!(ring.call_id, call.call_id);
    assert_eq!(ring.peer_id, alice.peer_id());
    assert!(ring.video && ring.incoming);
    bob.accept_call(&ring.call_id).await.unwrap();
    let bob_media = bob.take_call_media(&ring.call_id).await.unwrap();

    for rx in [&mut alice_rx, &mut bob_rx] {
        call_state(rx, "active call", |c| {
            c.state == parolnet_app::CallState::Active
        })
        .await;
    }
    let (a, b) = tokio::join!(
        exchange_media(alice_media, 25),
        exchange_media(bob_media, 25)
    );
    assert!(a.0 >= 25 && a.1 >= 25, "alice received audio/video {a:?}");
    assert!(b.0 >= 25 && b.1 >= 25, "bob received audio/video {b:?}");

    alice.hangup(&call.call_id);
    let end = call_state(&mut bob_rx, "remote hang-up", |c| c.is_over()).await;
    assert_eq!(
        end.state,
        parolnet_app::CallState::Ended(parolnet_app::CallEnd::RemoteHungUp)
    );

    // A declined call.
    let call2 = bob.start_call(alice.peer_id(), false).await.unwrap();
    let ring2 = call_state(&mut alice_rx, "second ring", |c| {
        c.call_id == call2.call_id && c.state == parolnet_app::CallState::Incoming
    })
    .await;
    assert!(!ring2.video);
    alice.reject_call(&ring2.call_id);
    let end2 = call_state(&mut bob_rx, "declined", |c| {
        c.call_id == call2.call_id && c.is_over()
    })
    .await;
    assert_eq!(
        end2.state,
        parolnet_app::CallState::Ended(parolnet_app::CallEnd::Rejected)
    );

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A WebSocket proxy in front of the relay that drops the client's `watch` frames: the
/// relay then never has a mutual watch for this client, so no presence is pushed to either
/// side. It stands for a contact who does not watch back, one beyond the relay's 256 watched
/// ids, or a push that was missed. Returns the proxy's `ws://` URL.
async fn relay_without_presence(relay: &Relay) -> String {
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let upstream = format!("ws://127.0.0.1:{}/ws", relay.port);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let Ok(client) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let Ok((server, _)) = tokio_tungstenite::connect_async(upstream).await else {
                    return;
                };
                let (mut client_tx, mut client_rx) = client.split();
                let (mut server_tx, mut server_rx) = server.split();
                let up = async {
                    while let Some(Ok(msg)) = client_rx.next().await {
                        let is_watch = matches!(&msg, Message::Text(t)
                            if serde_json::from_str::<serde_json::Value>(t.as_str())
                                .is_ok_and(|v| v["type"] == "watch"));
                        if !is_watch && server_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                };
                let down = async {
                    while let Some(Ok(msg)) = server_rx.next().await {
                        if client_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! {
                    _ = up => {}
                    _ = down => {}
                }
            });
        }
    });
    url
}

async fn path(rx: &mut UnboundedReceiver<AppEvent>, what: &str, secs: u64, want: PathState) {
    wait_for(
        rx,
        what,
        secs,
        |e| matches!(e, AppEvent::Path { state, .. } if *state == want),
    )
    .await;
}

/// The bug this pins: the relay answered an offer with `peer_offline`, no message is queued
/// for the contact and no presence push will ever say it is back. The contact used to stay
/// "offline" for good; now it is probed with backoff and the connection comes back by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnects_by_itself_after_peer_offline_without_a_presence_push() {
    let relay = start_relay().await;
    let dir = unique_dir("probe");
    let mut alice_cfg = config(&dir, &relay, "alice");
    alice_cfg.relay_url = relay_without_presence(&relay).await;
    // Probe quickly (the defaults start at 15 s).
    alice_cfg.reconnect.first_probe = Duration::from_millis(400);
    let (alice, mut alice_rx) = start(alice_cfg).await;
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    path(&mut alice_rx, "paired (alice)", 30, PathState::Direct).await;
    path(&mut bob_rx, "paired (bob)", 30, PathState::Direct).await;
    let bob_id = bob.peer_id().to_owned();

    // Bob goes away. No presence push reaches Alice: she notices the connection closing,
    // retries, and the relay answers `peer_offline`.
    bob.shutdown().await;
    drop(bob_rx);
    path(
        &mut alice_rx,
        "bob offline by error",
        40,
        PathState::Offline,
    )
    .await;
    let snap = alice.snapshot().await.unwrap();
    assert_eq!(snap.contacts[0].queued, 0, "nothing is queued for bob");
    assert_eq!(snap.contacts[0].path, PathState::Offline);

    // Probes go out meanwhile and are answered `peer_offline`: still offline, quietly.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        alice.snapshot().await.unwrap().contacts[0].path,
        PathState::Offline
    );

    // Bob comes back. He has nothing to send and learns nothing about Alice (no mutual
    // watch), so he does not offer: Alice's next probe finds him.
    let (bob2, mut bob2_rx) = start(config(&dir, &relay, "bob")).await;
    assert_eq!(bob2.peer_id(), bob_id);
    registered(&mut bob2_rx).await;
    path(&mut alice_rx, "alice reconnected", 30, PathState::Direct).await;
    path(&mut bob2_rx, "bob answered", 30, PathState::Direct).await;
    let sent = alice.send_text(&bob_id, "found you").await.unwrap();
    assert_eq!(sent.state, DeliveryState::Queued);
    received(&mut bob2_rx, alice.peer_id(), "found you").await;

    alice.shutdown().await;
    bob2.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wait for the TURN server to hold exactly `want` allocations (releases are asynchronous).
async fn allocations(turn: &TestTurnServer, want: usize, what: &str) {
    for _ in 0..400 {
        if turn.live_allocations() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{what}: {} allocations, expected {want}",
        turn.live_allocations()
    );
}

const TURN_USER: &str = "pat";
const TURN_PASS: &str = "the user's own turn password";

fn turn_settings(server: &TestTurnServer, relay_only: bool) -> TurnSettings {
    TurnSettings {
        uri: server.uri(),
        username: TURN_USER.into(),
        password: TURN_PASS.into(),
        relay_only,
    }
}

/// Both sides relay-only through the user's TURN server: pairing, chat and a video call all
/// cross it, the settings survive a restart, and clearing them goes back to direct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_only_through_the_users_own_turn_server() {
    let relay = start_relay().await;
    let turn = TestTurnServer::start(TURN_USER, TURN_PASS).await.unwrap();
    let dir = unique_dir("turn");
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;

    // Nothing is configured by default, and bad settings are refused.
    let snap = alice.snapshot().await.unwrap();
    assert!(!snap.turn_configured && !snap.relay_only);
    assert_eq!(alice.turn_settings().await.unwrap(), None);
    for (uri, user, pass) in [
        ("turns:turn.example:5349", TURN_USER, TURN_PASS),
        ("turn:turn.example:3478?transport=tcp", TURN_USER, TURN_PASS),
        ("turn.example:3478", TURN_USER, TURN_PASS),
        ("turn:turn.example:3478", "", TURN_PASS),
        ("turn:turn.example:3478", TURN_USER, ""),
    ] {
        let bad = TurnSettings {
            uri: uri.into(),
            username: user.into(),
            password: pass.into(),
            relay_only: true,
        };
        assert!(
            matches!(
                alice.set_turn_settings(bad).await,
                Err(parolnet_app::AppError::Config(_))
            ),
            "{uri} {user:?}"
        );
    }
    assert!(!alice.snapshot().await.unwrap().turn_configured);

    alice
        .set_turn_settings(turn_settings(&turn, true))
        .await
        .unwrap();
    bob.set_turn_settings(turn_settings(&turn, true))
        .await
        .unwrap();
    let snap = alice.snapshot().await.unwrap();
    assert!(snap.turn_configured && snap.relay_only);
    assert!(!format!("{snap:?}").contains(TURN_PASS));
    let stored = alice.turn_settings().await.unwrap().unwrap();
    assert_eq!(stored, turn_settings(&turn, true));
    assert!(!format!("{stored:?}").contains(TURN_PASS));

    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    path(&mut alice_rx, "relayed path (alice)", 40, PathState::Direct).await;
    path(&mut bob_rx, "relayed path (bob)", 40, PathState::Direct).await;
    allocations(&turn, 2, "one allocation per side").await;
    let before_chat = turn.relayed_datagrams();
    assert!(before_chat > 20, "ICE, DTLS and SCTP crossed the relay");
    bob.send_text(alice.peer_id(), "through my own relay")
        .await
        .unwrap();
    received(&mut alice_rx, bob.peer_id(), "through my own relay").await;
    assert!(turn.relayed_datagrams() > before_chat);

    // A call's own connection is relayed too.
    let call = alice.start_call(bob.peer_id(), true).await.unwrap();
    let alice_media = alice.take_call_media(&call.call_id).await.unwrap();
    let ring = call_state(&mut bob_rx, "incoming call", |c| {
        c.state == parolnet_app::CallState::Incoming
    })
    .await;
    bob.accept_call(&ring.call_id).await.unwrap();
    let bob_media = bob.take_call_media(&ring.call_id).await.unwrap();
    for rx in [&mut alice_rx, &mut bob_rx] {
        call_state(rx, "active call", |c| {
            c.state == parolnet_app::CallState::Active
        })
        .await;
    }
    allocations(&turn, 4, "the call allocated on both sides").await;
    let before_media = turn.relayed_datagrams();
    let (a, b) = tokio::join!(
        exchange_media(alice_media, 25),
        exchange_media(bob_media, 25)
    );
    assert!(a.0 >= 25 && a.1 >= 25, "alice received audio/video {a:?}");
    assert!(b.0 >= 25 && b.1 >= 25, "bob received audio/video {b:?}");
    assert!(turn.relayed_datagrams() > before_media + 100);
    alice.hangup(&call.call_id);
    call_state(&mut bob_rx, "remote hang-up", |c| c.is_over()).await;
    allocations(&turn, 2, "the call's allocations are gone").await;

    // The settings are part of the saved state.
    alice.shutdown().await;
    drop(alice_rx);
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    registered(&mut alice_rx).await;
    assert_eq!(
        alice.turn_settings().await.unwrap(),
        Some(turn_settings(&turn, true))
    );
    path(
        &mut alice_rx,
        "relayed again after a restart",
        40,
        PathState::Direct,
    )
    .await;

    // Clearing them applies at once: the connection is rebuilt without the relay.
    alice.clear_turn_settings().await.unwrap();
    bob.clear_turn_settings().await.unwrap();
    assert!(!alice.snapshot().await.unwrap().turn_configured);
    let mut settled = false;
    for _ in 0..800 {
        let direct = |snap: parolnet_app::Snapshot| snap.contacts[0].path == PathState::Direct;
        if turn.live_allocations() == 0
            && direct(bob.snapshot().await.unwrap())
            && direct(alice.snapshot().await.unwrap())
        {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(settled, "direct again, with no allocation left");
    while bob_rx.try_recv().is_ok() {}
    let idle = turn.relayed_datagrams();
    let sent = alice.send_text(bob.peer_id(), "direct now").await.unwrap();
    assert_eq!(sent.state, DeliveryState::Queued);
    received(&mut bob_rx, alice.peer_id(), "direct now").await;
    assert_eq!(turn.relayed_datagrams(), idle, "nothing crosses the relay");

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Relay-only with a TURN server that does not answer: the contact shows as having no path
/// (with a notice saying why) and no direct connection is made behind the user's back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_only_without_a_reachable_turn_server_shows_no_path() {
    let relay = start_relay().await;
    let dir = unique_dir("noturn");
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    bob.set_turn_settings(TurnSettings {
        uri: format!("turn:{}", silent.local_addr().unwrap()),
        username: TURN_USER.into(),
        password: TURN_PASS.into(),
        relay_only: true,
    })
    .await
    .unwrap();

    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    let mut noticed = false;
    wait_for(&mut bob_rx, "no path without the relay", 30, |e| {
        if let AppEvent::Notice(n) = e {
            assert!(n.contains("TURN"), "{n}");
            assert!(!n.contains(TURN_PASS), "{n}");
            noticed = true;
        }
        matches!(
            e,
            AppEvent::Path {
                state: PathState::NoDirectPath,
                ..
            }
        )
    })
    .await;
    assert!(noticed, "the user is told why");
    // Alice never heard from Bob: no offer left his device without a relay candidate.
    let reached = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match alice_rx.recv().await {
                Some(AppEvent::ContactAdded(_)) | Some(AppEvent::Path { .. }) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(!reached, "a connection was made without the relay");
    assert_eq!(
        bob.snapshot().await.unwrap().contacts[0].path,
        PathState::NoDirectPath
    );

    // Fixing the settings (here: removing the server) retries at once.
    bob.clear_turn_settings().await.unwrap();
    path(&mut bob_rx, "direct after the fix", 30, PathState::Direct).await;
    wait_for(&mut alice_rx, "paired after the fix", 30, |e| {
        matches!(e, AppEvent::ContactAdded(_))
    })
    .await;

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Network changes, renegotiation, bitrate and quality ─────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A call's media driven by the test: opaque audio and video frames go out all the time
/// (the core drops what is not negotiated), and what comes back is counted.
#[derive(Clone, Default)]
struct MediaProbe {
    audio: Arc<AtomicUsize>,
    video: Arc<AtomicUsize>,
    bitrates: Arc<Mutex<Vec<u32>>>,
    remote_video: Arc<Mutex<Vec<bool>>>,
    local_video: Arc<Mutex<Vec<bool>>>,
}

impl MediaProbe {
    fn start(media: parolnet_app::CallMedia) -> MediaProbe {
        use parolnet_app::{MediaEvent, MediaKind};
        let probe = MediaProbe::default();
        let parolnet_app::CallMedia { frames, mut events } = media;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            loop {
                tick.tick().await;
                if !frames.send(MediaKind::Audio, vec![0xf8; 60], 960)
                    || !frames.send(MediaKind::Video, vec![0x10; 2000], 1800)
                {
                    break;
                }
            }
        });
        let seen = probe.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    MediaEvent::Rtp {
                        kind: MediaKind::Audio,
                        ..
                    } => {
                        seen.audio.fetch_add(1, Ordering::Relaxed);
                    }
                    MediaEvent::Rtp {
                        kind: MediaKind::Video,
                        ..
                    } => {
                        seen.video.fetch_add(1, Ordering::Relaxed);
                    }
                    MediaEvent::TargetBitrate { bps } => seen.bitrates.lock().unwrap().push(bps),
                    MediaEvent::RemoteVideo { sending } => {
                        seen.remote_video.lock().unwrap().push(sending)
                    }
                    MediaEvent::LocalVideo { sending } => {
                        seen.local_video.lock().unwrap().push(sending)
                    }
                    _ => {}
                }
            }
        });
        probe
    }

    fn audio(&self) -> usize {
        self.audio.load(Ordering::Relaxed)
    }

    fn video(&self) -> usize {
        self.video.load(Ordering::Relaxed)
    }

    /// Wait until `more` further packets of each asked kind have arrived.
    async fn more(&self, what: &str, audio: usize, video: usize) {
        let (a0, v0) = (self.audio(), self.video());
        for _ in 0..600 {
            if self.audio() >= a0 + audio && self.video() >= v0 + video {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "{what}: audio {} (+{audio} wanted from {a0}), video {} (+{video} from {v0})",
            self.audio(),
            self.video()
        );
    }
}

/// Start a call from `caller` to `callee` and wait until it is active on both sides.
async fn active_call(
    caller: (&AppHandle, &mut UnboundedReceiver<AppEvent>),
    callee: (&AppHandle, &mut UnboundedReceiver<AppEvent>),
    video: bool,
) -> (String, MediaProbe, MediaProbe) {
    let call = caller
        .0
        .start_call(callee.0.peer_id(), video)
        .await
        .unwrap();
    let caller_media = MediaProbe::start(caller.0.take_call_media(&call.call_id).await.unwrap());
    let ring = call_state(callee.1, "incoming call", |c| {
        c.state == parolnet_app::CallState::Incoming
    })
    .await;
    assert_eq!(ring.video, video);
    callee.0.accept_call(&ring.call_id).await.unwrap();
    let callee_media = MediaProbe::start(callee.0.take_call_media(&ring.call_id).await.unwrap());
    for rx in [caller.1, callee.1] {
        call_state(rx, "active call", |c| {
            c.state == parolnet_app::CallState::Active
        })
        .await;
    }
    (call.call_id, caller_media, callee_media)
}

/// Wait until the contact's connection has completed `want` ICE restarts.
async fn ice_restarts(app: &AppHandle, want: u32, what: &str) {
    for _ in 0..400 {
        if app.snapshot().await.unwrap().contacts[0].ice_restarts >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{what}: {} ICE restarts, expected {want}",
        app.snapshot().await.unwrap().contacts[0].ice_restarts
    );
}

/// Everything waiting in the event channel.
fn drain(rx: &mut UnboundedReceiver<AppEvent>) -> Vec<AppEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

/// A network change restarts ICE on the data connection through the relay (`rtc_offer` /
/// `rtc_answer` again) and on the call through `reoffer` / `reanswer` inside the session:
/// neither is torn down, the path never stops being direct, and chat and media go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_network_change_restarts_ice_instead_of_rebuilding() {
    let relay = start_relay().await;
    let dir = unique_dir("restart");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir).await;
    bob.send_text(alice.peer_id(), "before").await.unwrap();
    received(&mut alice_rx, bob.peer_id(), "before").await;
    assert_eq!(alice.snapshot().await.unwrap().contacts[0].ice_restarts, 0);
    drain(&mut alice_rx);
    drain(&mut bob_rx);

    // Alice's interfaces changed.
    alice.network_changed();
    ice_restarts(&alice, 1, "alice's restart").await;
    ice_restarts(&bob, 1, "the restart bob answered").await;
    let sent = alice
        .send_text(bob.peer_id(), "after the restart")
        .await
        .unwrap();
    assert_eq!(sent.state, DeliveryState::Queued);
    received(&mut bob_rx, alice.peer_id(), "after the restart").await;
    bob.send_text(alice.peer_id(), "and back").await.unwrap();
    received(&mut alice_rx, bob.peer_id(), "and back").await;
    // And from the other side, the one that answered the first offer of the connection.
    bob.network_changed();
    ice_restarts(&bob, 2, "bob's restart").await;
    ice_restarts(&alice, 2, "the restart alice answered").await;
    // Both at once: the crossing offers are settled, and one restart is counted.
    alice.network_changed();
    bob.network_changed();
    ice_restarts(&alice, 3, "the crossed restarts (alice)").await;
    ice_restarts(&bob, 3, "the crossed restarts (bob)").await;
    alice.send_text(bob.peer_id(), "still here").await.unwrap();
    received(&mut bob_rx, alice.peer_id(), "still here").await;

    // The connection was never rebuilt: no path change was reported on either side.
    for events in [drain(&mut alice_rx), drain(&mut bob_rx)] {
        for event in events {
            assert!(
                !matches!(event, AppEvent::Path { .. } | AppEvent::Notice(_)),
                "{event:?}"
            );
        }
    }
    assert_eq!(
        alice.snapshot().await.unwrap().contacts[0].path,
        PathState::Direct
    );

    // The same during a call: the call's own connection restarts too and media goes on.
    let (call_id, alice_media, bob_media) =
        active_call((&alice, &mut alice_rx), (&bob, &mut bob_rx), true).await;
    alice_media
        .more("media before the change (alice)", 25, 25)
        .await;
    bob_media
        .more("media before the change (bob)", 25, 25)
        .await;
    let changes = |rx: &mut UnboundedReceiver<AppEvent>| {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                AppEvent::CallQuality { quality, .. } => Some(quality.stats.path_changes),
                AppEvent::Call(c) => {
                    assert!(!c.is_over(), "{c:?}");
                    None
                }
                _ => None,
            })
            .max()
    };
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let before = changes(&mut alice_rx).expect("a quality report").max(1);
    alice.network_changed();
    let mut moved = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if changes(&mut alice_rx).is_some_and(|n| n > before) {
            moved = true;
            break;
        }
    }
    assert!(
        moved,
        "the call's transport selected a pair again after its ICE restart"
    );
    alice_media
        .more("media after the change (alice)", 50, 50)
        .await;
    bob_media.more("media after the change (bob)", 50, 50).await;
    ice_restarts(&alice, 4, "the data connection restarted with the call").await;
    alice.hangup(&call_id);
    call_state(&mut bob_rx, "hang-up", |c| c.is_over()).await;

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A contact whose app knows no ICE restart (the PWA, the web app today) is never sent one:
/// its connection is left as it is, and a call with it stays as it was set up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contact_that_does_not_renegotiate_keeps_working_as_before() {
    let relay = start_relay().await;
    let dir = unique_dir("norestart");
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let mut old = config(&dir, &relay, "bob");
    old.renegotiation = false;
    let (bob, mut bob_rx) = start(old).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    path(&mut alice_rx, "paired (alice)", 30, PathState::Direct).await;
    path(&mut bob_rx, "paired (bob)", 30, PathState::Direct).await;
    drain(&mut alice_rx);
    drain(&mut bob_rx);

    alice.network_changed();
    bob.network_changed();
    tokio::time::sleep(Duration::from_secs(2)).await;
    for app in [&alice, &bob] {
        let contact = &app.snapshot().await.unwrap().contacts[0];
        assert_eq!((contact.ice_restarts, contact.path), (0, PathState::Direct));
    }
    alice.send_text(bob.peer_id(), "as before").await.unwrap();
    received(&mut bob_rx, alice.peer_id(), "as before").await;
    assert!(
        drain(&mut alice_rx)
            .iter()
            .all(|e| !matches!(e, AppEvent::Path { .. })),
        "nothing happened to the connection"
    );

    // A video call: the camera toggle does not renegotiate (black is sent instead), and the
    // call is not told to change.
    let (call_id, alice_media, bob_media) =
        active_call((&alice, &mut alice_rx), (&bob, &mut bob_rx), true).await;
    alice_media.more("video from bob", 10, 10).await;
    bob_media.more("video from alice", 10, 10).await;
    assert_eq!(
        alice.set_call_video(&call_id, false).await.unwrap(),
        parolnet_app::VideoChange::Unchanged
    );
    assert_eq!(
        bob.set_call_video(&call_id, false).await.unwrap(),
        parolnet_app::VideoChange::Unchanged
    );
    alice.network_changed();
    // The stream is still there both ways (what the client sends on it is its business).
    bob_media
        .more("video from alice after 'camera off'", 25, 25)
        .await;
    alice_media
        .more("video from bob after 'camera off'", 25, 25)
        .await;
    let calls: Vec<parolnet_app::CallInfo> = drain(&mut alice_rx)
        .into_iter()
        .filter_map(|e| match e {
            AppEvent::Call(c) => Some(c),
            _ => None,
        })
        .collect();
    assert!(
        calls.iter().all(|c| !c.renegotiable && c.local_video),
        "{calls:?}"
    );
    alice.hangup(&call_id);
    call_state(&mut bob_rx, "hang-up", |c| c.is_over()).await;

    // An audio call cannot gain video.
    let (call_id, alice_media, _bob_media) =
        active_call((&alice, &mut alice_rx), (&bob, &mut bob_rx), false).await;
    alice_media.more("audio", 10, 0).await;
    assert!(matches!(
        alice.set_call_video(&call_id, true).await,
        Err(parolnet_app::AppError::CannotRenegotiate)
    ));
    assert_eq!(
        alice.set_call_video(&call_id, false).await.unwrap(),
        parolnet_app::VideoChange::Unchanged
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(alice_media.video(), 0);
    alice.hangup(&call_id);
    call_state(&mut bob_rx, "hang-up", |c| c.is_over()).await;

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// An audio call gains video by renegotiation, in both directions, and a camera that is
/// turned off stops its stream; the encoder is told what the path carries and the UI how
/// good the connection is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_gains_and_loses_video_by_renegotiation() {
    use parolnet_app::VideoChange;
    let relay = start_relay().await;
    let dir = unique_dir("upgrade");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir).await;
    let (call_id, alice_media, bob_media) =
        active_call((&alice, &mut alice_rx), (&bob, &mut bob_rx), false).await;
    alice_media.more("audio (alice)", 25, 0).await;
    bob_media.more("audio (bob)", 25, 0).await;
    assert_eq!((alice_media.video(), bob_media.video()), (0, 0));

    // The congestion controller's estimate reached the client's media end at once.
    assert_eq!(alice_media.bitrates.lock().unwrap().first(), Some(&300_000));
    assert_eq!(bob_media.bitrates.lock().unwrap().first(), Some(&300_000));

    // Alice turns her camera on.
    assert_eq!(
        alice.set_call_video(&call_id, true).await.unwrap(),
        VideoChange::Renegotiating
    );
    let info = call_state(&mut bob_rx, "bob sees alice's video", |c| c.remote_video).await;
    assert!(info.video && !info.local_video && info.renegotiable);
    let info = call_state(&mut alice_rx, "alice's video is sent", |c| c.local_video).await;
    assert!(info.video && !info.remote_video && info.renegotiable);
    bob_media.more("alice's video", 25, 25).await;
    assert_eq!(alice_media.video(), 0, "bob's camera is off");
    assert_eq!(*bob_media.remote_video.lock().unwrap(), [true]);
    assert_eq!(alice_media.local_video.lock().unwrap().last(), Some(&true));

    // Bob turns his on.
    assert_eq!(
        bob.set_call_video(&call_id, true).await.unwrap(),
        VideoChange::Renegotiating
    );
    call_state(&mut alice_rx, "alice sees bob's video", |c| c.remote_video).await;
    alice_media.more("bob's video", 25, 25).await;

    // Alice turns hers off: bob is told and her stream stops; his goes on.
    assert_eq!(
        alice.set_call_video(&call_id, false).await.unwrap(),
        VideoChange::Renegotiating
    );
    let info = call_state(&mut bob_rx, "bob sees alice's video end", |c| {
        !c.remote_video
    })
    .await;
    assert!(info.video && info.local_video, "{info:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stopped = bob_media.video();
    alice_media.more("bob's video continues", 25, 25).await;
    assert_eq!(bob_media.video(), stopped, "no video from alice any more");
    assert_eq!(*bob_media.remote_video.lock().unwrap(), [true, false]);

    // Both at once: alice on again, bob off. The crossing offers are settled.
    let (a, b) = tokio::join!(
        alice.set_call_video(&call_id, true),
        bob.set_call_video(&call_id, false)
    );
    assert_eq!(
        (a.unwrap(), b.unwrap()),
        (VideoChange::Renegotiating, VideoChange::Renegotiating)
    );
    call_state(&mut bob_rx, "alice's video is back and bob's is off", |c| {
        c.remote_video && !c.local_video
    })
    .await;
    call_state(&mut alice_rx, "the same seen by alice", |c| {
        c.local_video && !c.remote_video
    })
    .await;
    bob_media.more("alice's video again", 25, 25).await;

    // The quality of the connection is reported about once a second while the call is
    // active: a host pair on loopback, nothing lost, nothing weak.
    let quality = wait_for(
        &mut alice_rx,
        "a quality report",
        10,
        |e| matches!(e, AppEvent::CallQuality { quality, .. } if quality.stats.send_bps > 0),
    )
    .await;
    let AppEvent::CallQuality {
        call_id: id,
        quality,
    } = quality
    else {
        unreachable!()
    };
    assert_eq!(id, call_id);
    assert_eq!(
        quality.stats.local_candidate,
        Some(parolnet_app::CandidateKind::Host)
    );
    assert!(
        quality.stats.rtt_ms.is_some_and(|rtt| rtt < 200),
        "{quality:?}"
    );
    assert!(quality.stats.available_bps.is_some());
    assert_eq!(quality.summary(), None, "{quality:?}");
    assert!(
        alice_media.bitrates.lock().unwrap().len() > 1,
        "the estimate moved"
    );

    alice.hangup(&call_id);
    call_state(&mut bob_rx, "hang-up", |c| c.is_over()).await;
    assert!(matches!(
        alice.set_call_video(&call_id, true).await,
        Err(parolnet_app::AppError::UnknownCall(_))
    ));
    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Without a pinned address the clients gather on every interface the machine has (IPv4 and
/// IPv6, whatever this machine's are) and watch them: pairing, chat, a restart and a call work
/// the same, and each side's offer names more than loopback when the machine has a network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_chat_and_a_call_on_every_interface() {
    // macOS's local-network privacy drops datagrams between a process's own sockets on the
    // machine's LAN and global addresses unless the process has that permission (a test run
    // from an agent or over SSH has not); loopback always works. Nothing to test there.
    let addresses = parolnet_rtc::net::local_addresses(&parolnet_rtc::SystemNetwork);
    let delivers = |ip: std::net::IpAddr| {
        let bind = |ip| std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0));
        let (Ok(a), Ok(b)) = (bind(ip), bind(ip)) else {
            return false;
        };
        let _ = b.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 8];
        b.local_addr()
            .is_ok_and(|to| a.send_to(b"probe", to).is_ok() && b.recv_from(&mut buf).is_ok())
    };
    if !addresses.iter().any(|ip| delivers(*ip)) {
        eprintln!("skipped: this machine does not deliver UDP between its own addresses");
        return;
    }
    let relay = start_relay().await;
    let dir = unique_dir("interfaces");
    let all_interfaces = |name: &str| {
        let mut cfg = config(&dir, &relay, name);
        cfg.bind_ip = None;
        cfg
    };
    let (alice, mut alice_rx) = start(all_interfaces("alice")).await;
    let (bob, mut bob_rx) = start(all_interfaces("bob")).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    path(&mut alice_rx, "paired (alice)", 40, PathState::Direct).await;
    path(&mut bob_rx, "paired (bob)", 40, PathState::Direct).await;
    bob.send_text(alice.peer_id(), "over whichever pair won")
        .await
        .unwrap();
    received(&mut alice_rx, bob.peer_id(), "over whichever pair won").await;

    alice.network_changed();
    ice_restarts(&alice, 1, "a restart on the real interfaces").await;
    alice.send_text(bob.peer_id(), "after it").await.unwrap();
    received(&mut bob_rx, alice.peer_id(), "after it").await;

    let (call_id, alice_media, bob_media) =
        active_call((&alice, &mut alice_rx), (&bob, &mut bob_rx), true).await;
    alice_media.more("media (alice)", 25, 25).await;
    bob_media.more("media (bob)", 25, 25).await;
    alice.hangup(&call_id);
    call_state(&mut bob_rx, "hang-up", |c| c.is_over()).await;
    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
