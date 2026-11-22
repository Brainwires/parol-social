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

    // The contact drops its connection (it stays registered on the relay). The app shows
    // `Connecting` as soon as the path is gone but keeps the verified connection through a
    // grace period (or an ICE restart) in case the path comes back; only once it gives the
    // connection up (`Unknown`, or `Offline` if the relay says so) is there no channel left
    // to hand a message to.
    peer.disconnect().await;
    app.wait("the connection given up", 30, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Unknown | PathState::Offline,
                ..
            }
        )
    })
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
    // A message leaves the queue when the contact's end has acknowledged it.
    for _ in 0..3 {
        app.wait("a delivered message marked sent", 10, |e| {
            matches!(
                e,
                AppEvent::MessageState {
                    state: DeliveryState::Sent,
                    ..
                }
            )
        })
        .await;
    }
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts[0].queued, 0);
}

// A message leaves the device's queue when the contact's end has acknowledged it, not when
// it is handed to a data channel. Here the contact's connection is gone but the app still
// holds its side of it (the grace period, or an ICE restart): messages sent now are handed
// to a channel nobody reads. They stay queued, are never shown as sent, and reach the
// contact, in order and once, over the next connection.
#[clause("PNP-005-SHOULD-017")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_given_to_a_dying_channel_stay_queued_and_arrive_over_the_next() {
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
    // A message on the live channel is acknowledged and only then shown as sent.
    let live = app.handle.send_text(&peer_id, "live").await.unwrap();
    assert_eq!(live.state, DeliveryState::Queued);
    let got = peer
        .receive(Duration::from_secs(10), |d| d.plaintext == b"live")
        .await;
    assert_eq!(
        got.last().map(|d| d.plaintext.as_slice()),
        Some(&b"live"[..])
    );
    app.wait("the live message marked sent", 10, |e| {
        matches!(e, AppEvent::MessageState { id, state: DeliveryState::Sent, .. } if *id == live.id)
    })
    .await;
    assert_eq!(app.handle.snapshot().await.unwrap().contacts[0].queued, 0);

    // The contact's connection ends. The app has not given its own side up yet: it takes
    // these messages while it still holds the channel.
    peer.disconnect().await;
    let mut ids = Vec::new();
    for text in ["first", "second", "third"] {
        let m = app.handle.send_text(&peer_id, text).await.unwrap();
        assert_eq!(m.state, DeliveryState::Queued, "{text}");
        ids.push(m.id);
        // One send slot each, so every one of them has been handed to the channel (or
        // kept back) before the next.
        tokio::time::sleep(Duration::from_millis(700)).await;
    }

    // Until the app gives the connection up, and after, none of them is shown as sent
    // and all of them are still stored.
    let mut marked_sent = Vec::new();
    app.wait_seeing(
        "the connection given up",
        40,
        |e| {
            matches!(
                e,
                AppEvent::Path {
                    state: PathState::Unknown | PathState::Offline,
                    ..
                }
            )
        },
        |e| {
            if let AppEvent::MessageState {
                id,
                state: DeliveryState::Sent,
                ..
            } = e
            {
                marked_sent.push(*id);
            }
        },
    )
    .await;
    assert!(
        marked_sent.is_empty(),
        "shown as sent on a channel nobody read: {marked_sent:?}"
    );
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts[0].queued, 3);
    let history = app.handle.messages(&peer_id).await.unwrap();
    for id in &ids {
        let m = history
            .iter()
            .find(|m| m.id == *id)
            .expect("in the history");
        assert_eq!(m.state, DeliveryState::Queued, "{}", m.text);
    }

    // The contact comes back with a new connection and binds it: the three arrive, in
    // order, each once, and only now leave the queue.
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
    for id in ids {
        app.wait("a resent message marked sent", 10, |e| {
            matches!(e, AppEvent::MessageState { id: got, state: DeliveryState::Sent, .. } if *got == id)
        })
        .await;
    }
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts[0].queued, 0);
    // Nothing more follows: no message was sent twice.
    let more = peer.receive(Duration::from_secs(2), |_| false).await;
    assert!(
        more.is_empty(),
        "sent again: {:?}",
        more.iter().map(|d| d.msg_type).collect::<Vec<_>>()
    );
}
