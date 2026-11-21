//! Two `parolnet-app` instances against a real relay binary in its default signaling-only
//! profile: QR-code pairing, encrypted chat both ways over the direct data channel, and the
//! sender-side queue across a restart (presence push brings the contact back); reconnecting
//! to a contact the relay called offline when no presence push ever comes; and chat and a
//! call relayed through the user's own TURN server (an in-process one here).
//!
//! The relay binary is `PAROLNET_RELAY_BIN` when set, else `parolnet-relay` next to this
//! test's target directory (built with `cargo build -p parolnet-relay-server` on demand).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use parolnet_app::{
    AppConfig, AppEvent, AppHandle, DeliveryState, Direction, PathState, RelayState, TurnSettings,
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

async fn start_relay() -> Relay {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = unique_dir("relay");
    let child = Command::new(relay_binary())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RELAY_PORT", port.to_string())
        .env("RELAY_KEY_FILE", dir.join("relay.key"))
        .env("RELAY_AUTHORITY_KEY_FILE", dir.join("relay-authority.cbor"))
        .env("RUST_LOG", "warn")
        // Every client shares 127.0.0.1 here.
        .env("RELAY_CONN_PER_MINUTE", "1000")
        .env("RELAY_MAX_PEERS_PER_IP", "16")
        .env("RELAY_MAX_CONNS_PER_IP", "32")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay");
    let relay = Relay { child, port, dir };
    for _ in 0..400 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return relay;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("relay did not listen on {port}");
}

fn config(dir: &Path, relay: &Relay, name: &str) -> AppConfig {
    let mut cfg = AppConfig::new(dir.join(name), format!("ws://127.0.0.1:{}/ws", relay.port));
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
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
    assert_eq!(sent.state, DeliveryState::Sent);
    received(&mut alice_rx, bob.peer_id(), "hello from bob").await;
    let reply = alice
        .send_text(bob.peer_id(), "hi bob, alice here")
        .await
        .unwrap();
    assert_eq!(reply.state, DeliveryState::Sent);
    received(&mut bob_rx, alice.peer_id(), "hi bob, alice here").await;
    for i in 0..5 {
        bob.send_text(alice.peer_id(), &format!("burst {i}"))
            .await
            .unwrap();
    }
    for i in 0..5 {
        received(&mut alice_rx, bob.peer_id(), &format!("burst {i}")).await;
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
    assert_eq!(sent.state, DeliveryState::Sent);
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
    assert_eq!(sent.state, DeliveryState::Sent);
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
