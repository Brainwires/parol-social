//! Two `parolnet-app` instances against a real relay binary in its default signaling-only
//! profile: QR-code pairing, encrypted chat both ways over the direct data channel, and the
//! sender-side queue across a restart (presence push brings the contact back).
//!
//! The relay binary is `PAROLNET_RELAY_BIN` when set, else `parolnet-relay` next to this
//! test's target directory (built with `cargo build -p parolnet-relay-server` on demand).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use parolnet_app::{
    AppConfig, AppEvent, AppHandle, DeliveryState, Direction, PathState, RelayState,
};
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
