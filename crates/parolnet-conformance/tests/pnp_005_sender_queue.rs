//! PNP-005 §5.10: with a signaling-only relay, offline delivery is the sender's job. The
//! client queues messages for an offline contact on the device, bounded in age and in size,
//! and delivers them over the direct data channel once the contact is there.

mod common;

use std::time::Duration;

use common::{App, RawPeer, Relay};
use parolnet_app::store::{
    QUEUE_MAX_AGE_MS, QUEUE_MAX_ENTRIES, QUEUE_MAX_PER_PEER, QueuedEnvelope, State,
};
use parolnet_app::{AppEvent, DeliveryState, PathState};
use parolnet_clause::clause;

fn entry(peer: &str, id: u64, created_ms: u64) -> QueuedEnvelope {
    QueuedEnvelope {
        peer_id: peer.to_owned(),
        envelope: format!("{id:08x}"),
        created_ms,
        message_id: Some(id),
    }
}

// The queue the client keeps is bounded three ways, and what falls out is reported so the
// message can be shown as dropped: by age, per contact, and overall.
#[clause("PNP-005-SHOULD-017")]
#[test]
fn the_sender_queue_is_bounded_in_age_and_size() {
    // Age: an entry older than the limit leaves when the next one is queued.
    let mut state = State::default();
    assert!(state.enqueue(entry("a", 1, 1_000), 1_000).is_empty());
    assert!(
        state
            .enqueue(entry("a", 2, 2_000), 1_000 + QUEUE_MAX_AGE_MS)
            .is_empty(),
        "an entry exactly at the age limit stays"
    );
    let dropped = state.enqueue(entry("b", 3, 0), 1_001 + QUEUE_MAX_AGE_MS);
    assert_eq!(dropped, [1], "the over-age entry, whoever it was for");
    assert_eq!(state.queued_for("a"), 1);

    // Per contact: the contact's oldest entries make room, other contacts keep theirs.
    let mut state = State::default();
    state.enqueue(entry("other", 9_000_000, 0), 0);
    let mut dropped = Vec::new();
    for id in 0..QUEUE_MAX_PER_PEER as u64 + 3 {
        dropped.extend(state.enqueue(entry("a", id, 0), 0));
    }
    assert_eq!(dropped, [0, 1, 2]);
    assert_eq!(state.queued_for("a"), QUEUE_MAX_PER_PEER);
    assert_eq!(state.queued_for("other"), 1);
    // Delivery order is the order of sending.
    let queued = state.take_queue_for("a");
    assert!(queued.windows(2).all(|w| w[0].message_id < w[1].message_id));
    assert_eq!(state.queued_for("a"), 0);

    // Overall: the oldest entries of the whole queue make room.
    let mut state = State::default();
    let mut dropped = Vec::new();
    for id in 0..QUEUE_MAX_ENTRIES as u64 + 2 {
        let peer = format!("peer{}", id % 50);
        dropped.extend(state.enqueue(entry(&peer, id, 0), 0));
    }
    assert_eq!(dropped, [0, 1]);
    assert_eq!(state.queue.len(), QUEUE_MAX_ENTRIES);
}

// End to end: messages for a contact that went away wait on the device (nothing is handed to
// the relay) and reach the contact, in order, over the next direct channel.
#[clause("PNP-005-SHOULD-017")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_for_an_absent_contact_wait_and_arrive_over_the_next_channel() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let peer_id = peer.id.peer_id.clone();
    peer.send_bootstrap();
    peer.receive(Duration::from_secs(10), |d| d.msg_type == 0x14)
        .await;
    let ours = peer.binding().encode();
    peer.send(0x14, &ours);
    app.wait("a direct path", 10, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Direct,
                ..
            }
        )
    })
    .await;

    // The contact drops its connection (it stays registered on the relay).
    peer.disconnect().await;
    app.wait(
        "the lost path",
        30,
        |e| matches!(e, AppEvent::Path { state, .. } if *state != PathState::Direct),
    )
    .await;
    for text in ["first", "second", "third"] {
        let m = app.handle.send_text(&peer_id, text).await.unwrap();
        assert_eq!(m.state, DeliveryState::Queued, "{text}");
    }
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts[0].queued, 3);
    assert!(
        !relay.log().contains("signaling_only"),
        "content was offered to the relay"
    );

    // The contact comes back with a new connection and binds it.
    peer.reconnect().await;
    let theirs = peer
        .receive(Duration::from_secs(10), |d| d.msg_type == 0x14)
        .await;
    assert_eq!(theirs.len(), 1);
    let ours = peer.binding().encode();
    peer.send(0x14, &ours);
    let got = peer
        .receive(Duration::from_secs(15), |d| d.plaintext == b"third")
        .await;
    let texts: Vec<&[u8]> = got.iter().map(|d| d.plaintext.as_slice()).collect();
    assert_eq!(texts, [&b"first"[..], b"second", b"third"]);
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts[0].queued, 0);
}
