//! PNP-001 §10.5.1 "Direct Data-Channel Binding" and the client's receive rules, observed
//! from outside: the real headless client (`parolnet-app`) against the real relay binary and
//! a scripted peer that pairs with it and then misbehaves on purpose (see `common`).

mod common;

use std::time::Duration;

use common::{App, RawPeer, Relay};
use parolnet_app::{AppError, AppEvent, DeliveryState, Direction, PathState};
use parolnet_clause::clause;
use parolnet_protocol::channel_binding::ChannelBinding;

const TEXT: u8 = 0x01;
const CALL_SIGNAL: u8 = 0x0B;
const CHANNEL_BINDING: u8 = 0x14;

fn is_path(ev: &AppEvent, want: PathState) -> bool {
    matches!(ev, AppEvent::Path { state, .. } if *state == want)
}

/// The app, and a scripted peer that scanned its code and holds the open channel.
async fn paired(relay: &Relay) -> (App, RawPeer) {
    let app = App::start(relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let peer = RawPeer::connect(relay, &code).await;
    (app, peer)
}

/// The peer's bootstrap envelope goes out and the app's binding comes back.
async fn bootstrap(app: &mut App, peer: &mut RawPeer) -> ChannelBinding {
    peer.send_bootstrap();
    app.wait("the contact", 20, |e| {
        matches!(e, AppEvent::ContactAdded(_))
    })
    .await;
    let got = peer
        .receive(Duration::from_secs(10), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    assert_eq!(
        got.len(),
        1,
        "the binding is the first envelope the app sends"
    );
    ChannelBinding::decode(&got[0].plaintext).expect("the app's binding decodes")
}

// The app sends its binding once it holds a session, holds content until the peer's binding
// has verified, and only then calls the path direct.
#[clause("PNP-001-MUST-079", "PNP-001-MUST-081", "PNP-001-SHOULD-018")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_and_calls_wait_for_the_peers_binding() {
    let relay = Relay::start(&[]).await;
    let (mut app, mut peer) = paired(&relay).await;
    let peer_id = peer.id.peer_id.clone();

    // MUST-079: one binding, naming the app's own fingerprints and the ones it received.
    let theirs = bootstrap(&mut app, &mut peer).await;
    theirs
        .verify(&peer.local_sdp, &peer.remote_sdp)
        .expect("the app's binding matches our view of the connection");

    // Before our binding: a message is accepted but stays on the device, a call is refused,
    // and nothing more reaches the channel.
    let msg = app.handle.send_text(&peer_id, "held").await.unwrap();
    assert_eq!(msg.state, DeliveryState::Queued);
    assert!(matches!(
        app.handle.start_call(&peer_id, false).await,
        Err(AppError::NotConnected(_))
    ));
    let early = peer.receive(Duration::from_secs(3), |_| false).await;
    assert!(
        early.is_empty(),
        "sent before the peer's binding verified: {:?}",
        early.iter().map(|d| d.msg_type).collect::<Vec<_>>()
    );
    let events = app.drain(Duration::from_millis(200)).await;
    assert!(
        !events.iter().any(|e| is_path(e, PathState::Direct)),
        "the path was shown as direct before the binding verified"
    );

    // Our binding verifies: the path is direct and the held message goes out.
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    app.wait("a direct path", 10, |e| is_path(e, PathState::Direct))
        .await;
    let late = peer
        .receive(Duration::from_secs(10), |d| d.msg_type == TEXT)
        .await;
    let kinds: Vec<u8> = late.iter().map(|d| d.msg_type).collect();
    assert_eq!(
        kinds,
        [TEXT],
        "exactly one binding was ever sent, then the text"
    );
    assert_eq!(late[0].plaintext, b"held");
    app.wait("the message marked sent", 10, |e| {
        matches!(e, AppEvent::MessageState { id, state: DeliveryState::Sent, .. } if *id == msg.id)
    })
    .await;
}

// No binding from the peer: the connection is closed about 20 seconds after the channel
// opened, was never shown as direct and carried no call signal.
#[clause("PNP-001-MUST-081")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_without_a_binding_is_closed_after_20_seconds() {
    let relay = Relay::start(&[]).await;
    let (mut app, mut peer) = paired(&relay).await;
    let peer_id = peer.id.peer_id.clone();
    bootstrap(&mut app, &mut peer).await;

    // We stay silent. A call attempt in the meantime sends nothing.
    assert!(app.handle.start_call(&peer_id, false).await.is_err());

    let mut direct = false;
    app.wait_seeing(
        "the unverified connection to be closed",
        40,
        |e| is_path(e, PathState::Unknown),
        |e| direct |= is_path(e, PathState::Direct),
    )
    .await;
    let waited = peer.opened_at.elapsed();
    assert!(!direct, "an unverified path was shown as direct");
    assert!(
        (Duration::from_secs(18)..=Duration::from_secs(26)).contains(&waited),
        "closed {waited:?} after the channel opened; the limit is 20 s"
    );
    let sent = peer.receive(Duration::from_secs(1), |_| false).await;
    assert!(
        !sent.iter().any(|d| d.msg_type == CALL_SIGNAL),
        "a call signal was sent on an unverified channel"
    );
    // The connection is gone: a binding now changes nothing.
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    let after = app.drain(Duration::from_secs(2)).await;
    assert!(!after.iter().any(|e| is_path(e, PathState::Direct)));
}

// A binding that names other fingerprints: the app closes the connection, tells the user and
// sends nothing further on it.
#[clause("PNP-001-MUST-080")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mismatched_binding_closes_the_connection_and_tells_the_user() {
    let relay = Relay::start(&[]).await;
    let (mut app, mut peer) = paired(&relay).await;
    let peer_id = peer.id.peer_id.clone();
    bootstrap(&mut app, &mut peer).await;
    app.handle.send_text(&peer_id, "held").await.unwrap();

    // What a peer behind an interposed relay would report: our fingerprint is not the one
    // the app saw.
    let mut forged = peer.binding();
    forged.local = vec![format!("sha-256 {}", ["AB"; 32].join(":"))];
    peer.send(CHANNEL_BINDING, &forged.encode());

    let mut told = false;
    app.wait_seeing(
        "the failed end-to-end check",
        10,
        |e| is_path(e, PathState::BindingFailed),
        |e| told |= matches!(e, AppEvent::Notice(n) if n.contains("end-to-end check")),
    )
    .await;
    if !told {
        let rest = app.drain(Duration::from_secs(2)).await;
        told = rest
            .iter()
            .any(|e| matches!(e, AppEvent::Notice(n) if n.contains("end-to-end check")));
    }
    assert!(told, "the user was not told");
    let sent = peer.receive(Duration::from_secs(2), |_| false).await;
    assert!(sent.is_empty(), "envelopes were sent after the mismatch");
}

// What the receive path does with envelopes it must not deliver: a wire length that is no
// bucket (MUST-036), a tag that does not verify (MUST-037), an unassigned message type
// (MUST-008) and a replay (MUST-038). Each is dropped without a trace and without disturbing
// the session: the next genuine message arrives.
#[clause(
    "PNP-001-MUST-008",
    "PNP-001-MUST-036",
    "PNP-001-MUST-037",
    "PNP-001-MUST-038"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn undeliverable_envelopes_are_dropped_silently() {
    let relay = Relay::start(&[]).await;
    let (mut app, mut peer) = paired(&relay).await;
    bootstrap(&mut app, &mut peer).await;
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    app.wait("a direct path", 10, |e| is_path(e, PathState::Direct))
        .await;

    let first = peer.seal(TEXT, b"one", None);
    peer.send_bytes(&first);

    // Not a bucket: one byte short, and one byte long.
    let whole = peer.seal(TEXT, b"never delivered (length)", None);
    peer.send_bytes(&whole[..whole.len() - 1]);
    let mut long = whole.clone();
    long.push(0);
    peer.send_bytes(&long);
    // A bucket-sized envelope whose ciphertext was altered in transit.
    let genuine = peer.seal(TEXT, b"never delivered (tag)", None);
    let mut env =
        <parolnet_protocol::codec::CborCodec as parolnet_protocol::ProtocolCodec>::decode(
            &parolnet_protocol::codec::CborCodec,
            &genuine,
        )
        .unwrap();
    env.encrypted_payload[0] ^= 0x01;
    let tampered =
        <parolnet_protocol::codec::CborCodec as parolnet_protocol::ProtocolCodec>::encode(
            &parolnet_protocol::codec::CborCodec,
            &env,
        )
        .unwrap();
    assert_eq!(tampered.len(), genuine.len());
    peer.send_bytes(&tampered);
    // Message types no revision assigns.
    for code in [0x00u8, 0x15, 0x7F, 0xFF] {
        peer.send(code, b"never delivered (type)");
    }
    // The first message again, byte for byte.
    peer.send_bytes(&first);

    peer.send(TEXT, b"two");

    let mut texts = Vec::new();
    let mut other = Vec::new();
    app.wait_seeing(
        "the second genuine message",
        20,
        |e| matches!(e, AppEvent::Message(m) if m.text == "two"),
        |e| match e {
            AppEvent::Message(m) if m.direction == Direction::Received => {
                texts.push(m.text.clone())
            }
            AppEvent::Notice(n) => other.push(n.clone()),
            AppEvent::Path { state, .. } => other.push(format!("{state:?}")),
            _ => {}
        },
    )
    .await;
    assert_eq!(texts, ["one", "two"]);
    assert!(other.is_empty(), "not silent: {other:?}");
    // And nothing was answered on the channel.
    let sent = peer.receive(Duration::from_secs(1), |_| false).await;
    assert!(sent.is_empty());
}

// On a direct path the client sends no cover traffic unless asked to: an idle verified
// channel stays silent.
#[clause("PNP-006-SHOULD-015")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_direct_channel_carries_no_decoys() {
    let relay = Relay::start(&[]).await;
    let (mut app, mut peer) = paired(&relay).await;
    bootstrap(&mut app, &mut peer).await;
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    app.wait("a direct path", 10, |e| is_path(e, PathState::Direct))
        .await;

    let mut frames = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, peer.events.recv()).await {
        if matches!(ev, parolnet_rtc::RtcEvent::DataChannelMessage { .. }) {
            frames += 1;
        }
    }
    assert_eq!(
        frames, 0,
        "the client sent {frames} frame(s) nobody asked for"
    );
    // Nor does it send anything to the relay but keepalives: the relay would refuse a decoy
    // `message` frame, and its log would say so.
    assert!(!relay.log().contains("signaling_only"));
}
