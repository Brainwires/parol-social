//! File transfer (PNP-010) between two `parolnet-app` instances over a real relay in its
//! signaling-only profile and a real WebRTC data channel on loopback: offer, accept,
//! decline, cancel, the limits, an offer made while the contact is away, and a transfer
//! that survives a killed connection and a restart of each app.
//!
//! `PAROLNET_TRANSFER_TEST_MIB` sets the size of the resumed transfer (default 48; the M1
//! bar is 2048, run by hand in release mode), `PAROLNET_TEST_DIR` where the files go.

mod support;

use std::time::{Duration, Instant};

use parolnet_app::{AppEvent, CancelReason, Direction, PathState, TransferState};
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_go_both_ways_and_offers_can_be_declined_or_cancelled() {
    init_tracing();
    let relay = start_relay().await;
    let dir = unique_dir("basic");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir, |cfg, name| {
        if name == "bob" {
            cfg.max_accept_size = 8 << 20;
        }
    })
    .await;

    // Alice → Bob, a few records. The name on Bob's side is never a path.
    let source = dir.join("holiday photo.jpg");
    let sha = write_file(&source, 3 * 1024 * 1024 + 123);
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    assert_eq!(offered.direction, Direction::Sent);
    assert_eq!(offered.state, TransferState::Offered);
    assert!(
        !offered.pending,
        "delivered at once over the verified channel"
    );
    assert_eq!(offered.name, "holiday photo.jpg");

    let incoming = transfer(&mut bob_rx, "the offer", 20, |t| t.id == offered.id).await;
    assert_eq!(incoming.direction, Direction::Received);
    assert_eq!(incoming.state, TransferState::Offered);
    assert_eq!(incoming.size, offered.size);
    assert_eq!(incoming.peer_id, alice.peer_id());
    assert_eq!(incoming.path, None);

    bob.accept_transfer(&incoming.id).await.unwrap();
    let done = transfer(&mut bob_rx, "the file on Bob's side", 60, |t| {
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;
    assert_eq!(done.bytes_done, done.size);
    let received = done.path.expect("a completed transfer names its file");
    assert_eq!(received.parent().unwrap(), dir.join("bob-downloads"));
    assert_eq!(received.file_name().unwrap(), "holiday photo.jpg");
    assert_eq!(hash_of(&received), sha);
    // Alice learns of the delivery from Bob's `complete`, not from having sent the bytes.
    let sent = transfer(&mut alice_rx, "complete on Alice's side", 30, |t| {
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;
    assert_eq!(sent.bytes_done, sent.size);
    // No part file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(dir.join("bob-downloads"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");

    // The same name again does not replace the first file.
    let again = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    assert_ne!(again.id, offered.id);
    transfer(&mut bob_rx, "the second offer", 20, |t| t.id == again.id).await;
    bob.accept_transfer(&again.id).await.unwrap();
    let done = transfer(&mut bob_rx, "the second file", 60, |t| {
        t.id == again.id && t.state == TransferState::Complete
    })
    .await;
    assert_eq!(
        done.path.as_ref().unwrap().file_name().unwrap(),
        "holiday photo (1).jpg"
    );
    assert_eq!(hash_of(done.path.as_ref().unwrap()), sha);
    assert_eq!(hash_of(&received), sha);

    // Bob → Alice: an empty file and a one-byte file.
    for (name, size) in [("empty.bin", 0u64), ("one.bin", 1)] {
        let path = dir.join(name);
        let sha = write_file(&path, size);
        let o = bob.offer_file(alice.peer_id(), &path).await.unwrap();
        transfer(&mut alice_rx, "Bob's offer", 20, |t| t.id == o.id).await;
        alice.accept_transfer(&o.id).await.unwrap();
        let done = transfer(&mut alice_rx, "Bob's file", 60, |t| {
            t.id == o.id && t.state == TransferState::Complete
        })
        .await;
        assert_eq!(hash_of(done.path.as_ref().unwrap()), sha);
        assert_eq!(std::fs::metadata(done.path.unwrap()).unwrap().len(), size);
        transfer(&mut bob_rx, "complete on Bob's side", 30, |t| {
            t.id == o.id && t.state == TransferState::Complete
        })
        .await;
    }

    // Declined.
    let o = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    transfer(&mut bob_rx, "an offer to decline", 20, |t| t.id == o.id).await;
    let declined = bob.decline_transfer(&o.id).await.unwrap();
    assert_eq!(declined.state, TransferState::Declined);
    transfer(&mut alice_rx, "declined on Alice's side", 20, |t| {
        t.id == o.id && t.state == TransferState::Declined
    })
    .await;
    assert!(
        bob.accept_transfer(&o.id).await.is_err(),
        "a declined offer is final"
    );

    // Cancelled by the sender before an answer; the receiver's later accept is refused.
    let o = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    transfer(&mut bob_rx, "an offer to be withdrawn", 20, |t| {
        t.id == o.id
    })
    .await;
    let cancelled = alice.cancel_transfer(&o.id).await.unwrap();
    assert_eq!(
        cancelled.state,
        TransferState::Cancelled {
            by_peer: false,
            reason: CancelReason::User
        }
    );
    transfer(&mut bob_rx, "cancelled on Bob's side", 20, |t| {
        t.id == o.id
            && t.state
                == TransferState::Cancelled {
                    by_peer: true,
                    reason: CancelReason::User,
                }
    })
    .await;
    assert!(bob.accept_transfer(&o.id).await.is_err());
    assert!(alice.cancel_transfer(&o.id).await.is_err(), "already over");

    // Above Bob's size limit: declined without asking him (PNP-010 §8).
    let big = dir.join("too-big.bin");
    write_file(&big, (8 << 20) + 1);
    let o = alice.offer_file(bob.peer_id(), &big).await.unwrap();
    transfer(&mut alice_rx, "auto-declined", 20, |t| {
        t.id == o.id && t.state == TransferState::Declined
    })
    .await;
    assert!(
        bob.transfers(None)
            .await
            .unwrap()
            .iter()
            .all(|t| t.id != o.id),
        "Bob was never shown the offer"
    );

    // What cannot be offered.
    assert!(
        alice
            .offer_file(bob.peer_id(), dir.join("missing"))
            .await
            .is_err()
    );
    assert!(alice.offer_file(bob.peer_id(), &dir).await.is_err());
    assert!(alice.offer_file(&"00".repeat(32), &source).await.is_err());
    assert!(alice.accept_transfer("nope").await.is_err());

    // The list keeps finished transfers, oldest first.
    let list = alice.transfers(Some(bob.peer_id())).await.unwrap();
    assert_eq!(list.len(), 7);
    assert_eq!(list[0].id, offered.id);
    assert!(list.iter().all(|t| t.state.is_over()));

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_made_while_the_contact_is_away_waits_on_this_device() {
    init_tracing();
    let relay = start_relay().await;
    let dir = unique_dir("away");
    let ((alice, mut alice_rx), (bob, bob_rx)) = paired_pair(&relay, &dir, |_, _| {}).await;
    bob.shutdown().await;
    drop(bob_rx);
    wait_for(&mut alice_rx, "bob offline", 60, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Offline | PathState::Unknown | PathState::Connecting,
                ..
            }
        )
    })
    .await;

    let source = dir.join("notes.txt");
    let sha = write_file(&source, 200_000);
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    assert!(offered.pending, "the offer waits on Alice's device");
    assert_eq!(offered.state, TransferState::Offered);

    // Alice restarts too: the offer, its key and the pending message are in the store.
    alice.shutdown().await;
    drop(alice_rx);
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let list = alice.transfers(None).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].pending);

    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    let incoming = transfer(&mut bob_rx, "the offer after coming back", 90, |t| {
        t.id == offered.id
    })
    .await;
    transfer(&mut alice_rx, "the offer delivered", 30, |t| {
        t.id == offered.id && !t.pending
    })
    .await;
    bob.accept_transfer(&incoming.id).await.unwrap();
    let done = transfer(&mut bob_rx, "the file", 60, |t| {
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;
    assert_eq!(hash_of(done.path.as_ref().unwrap()), sha);
    transfer(&mut alice_rx, "complete", 30, |t| {
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wait until the transfer has moved at least `bytes`, returning the report that said so.
async fn progress_to(
    rx: &mut Events,
    id: &str,
    bytes: u64,
    secs: u64,
) -> parolnet_app::TransferInfo {
    transfer(rx, &format!("{bytes} bytes moved"), secs, |t| {
        t.id == id && (t.bytes_done >= bytes || t.state == TransferState::Complete)
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_survives_a_killed_connection_and_a_restart_of_each_app() {
    init_tracing();
    let mib: u64 = std::env::var("PAROLNET_TRANSFER_TEST_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48);
    let size = mib * 1024 * 1024 + 4321;
    // Generous for the 2 GiB run by hand; a hang still fails.
    let patience = 120 + mib;
    let relay = start_relay().await;
    let dir = unique_dir("resume");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir, |_, _| {}).await;

    let source = dir.join("big.bin");
    let sha = write_file(&source, size);
    let started = Instant::now();
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    let hashed_in = started.elapsed();
    let id = offered.id.clone();
    transfer(&mut bob_rx, "the offer", 30, |t| t.id == id).await;
    let started = Instant::now();
    bob.accept_transfer(&id).await.unwrap();

    // 1. The connection is killed a quarter of the way in.
    let before = progress_to(&mut bob_rx, &id, size / 4, patience).await;
    assert_ne!(
        before.state,
        TransferState::Complete,
        "too fast to interrupt"
    );
    bob.disconnect(alice.peer_id());
    transfer(&mut bob_rx, "waiting after the cut", 30, |t| {
        t.id == id && t.state == TransferState::Waiting
    })
    .await;
    let stored = bob.transfers(None).await.unwrap()[0].bytes_done;
    assert!(stored >= size / 4, "what arrived is kept: {stored}");
    bob.connect(alice.peer_id());
    // It goes on from where it was, on a new channel of a new connection.
    let resumed = transfer(&mut bob_rx, "active again", 90, |t| {
        t.id == id && t.state == TransferState::Active
    })
    .await;
    assert!(
        resumed.bytes_done >= stored,
        "resumed at {} after {stored} were stored",
        resumed.bytes_done
    );
    // The sender starts at the record the receiver named, not at zero: its first report on
    // the new channel is exactly what the receiver had stored.
    transfer(&mut alice_rx, "the sender waiting after the cut", 90, |t| {
        t.id == id && t.state == TransferState::Waiting && t.bytes_done > 0
    })
    .await;
    let sender_view = transfer(&mut alice_rx, "the sender active again", 90, |t| {
        t.id == id && t.state == TransferState::Active
    })
    .await;
    assert_eq!(
        sender_view.bytes_done, stored,
        "the sender resumed where the receiver was"
    );

    // 2. The receiving app is killed half way and started again.
    let at = progress_to(&mut bob_rx, &id, size / 2, patience).await;
    assert_ne!(at.state, TransferState::Complete, "too fast to interrupt");
    bob.shutdown().await;
    drop(bob_rx);
    let (bob, mut bob_rx) = start(config(&dir, &relay, "bob")).await;
    let kept = bob.transfers(None).await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].state, TransferState::Waiting);
    let stored = kept[0].bytes_done;
    assert!(
        stored >= size / 4 && stored < size,
        "the store kept the checkpoint: {stored}"
    );
    let resumed = transfer(
        &mut bob_rx,
        "active after the receiver's restart",
        120,
        |t| t.id == id && t.state == TransferState::Active,
    )
    .await;
    assert!(resumed.bytes_done >= stored);

    // 3. The sending app is killed three quarters in and started again.
    let at = progress_to(&mut bob_rx, &id, size / 4 * 3, patience).await;
    assert_ne!(at.state, TransferState::Complete, "too fast to interrupt");
    alice.shutdown().await;
    drop(alice_rx);
    let (alice, mut alice_rx) = start(config(&dir, &relay, "alice")).await;
    let kept = alice.transfers(None).await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].state, TransferState::Waiting);

    let done = transfer(&mut bob_rx, "the whole file", patience, |t| {
        t.id == id && t.state == TransferState::Complete
    })
    .await;
    let took = started.elapsed();
    let received = done.path.expect("the received file");
    assert_eq!(std::fs::metadata(&received).unwrap().len(), size);
    assert_eq!(
        hash_of(&received),
        sha,
        "the received file is the sent file"
    );
    transfer(&mut alice_rx, "complete on the sender", 60, |t| {
        t.id == id && t.state == TransferState::Complete
    })
    .await;
    eprintln!(
        "{mib} MiB with one killed connection and two restarts: {:.1} s ({:.1} MiB/s overall); \
         hashing the source for the offer took {:.2} s",
        took.as_secs_f64(),
        mib as f64 / took.as_secs_f64(),
        hashed_in.as_secs_f64()
    );

    // Nothing is left but the file; the transfers are final on both sides and survive.
    let names: Vec<_> = std::fs::read_dir(dir.join("bob-downloads"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("big.bin")]);
    alice.shutdown().await;
    bob.shutdown().await;
    let (alice, _alice_rx) = start(config(&dir, &relay, "alice")).await;
    assert_eq!(
        alice.transfers(None).await.unwrap()[0].state,
        TransferState::Complete
    );
    alice.shutdown().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_that_changed_after_the_offer_is_not_sent() {
    init_tracing();
    let relay = start_relay().await;
    let dir = unique_dir("changed");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir, |_, _| {}).await;
    let source = dir.join("draft.txt");
    write_file(&source, 300_000);
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    transfer(&mut bob_rx, "the offer", 20, |t| t.id == offered.id).await;
    // The file is replaced by one of another size before Bob accepts.
    write_file(&source, 300_001);
    bob.accept_transfer(&offered.id).await.unwrap();
    let unavailable = TransferState::Cancelled {
        by_peer: false,
        reason: CancelReason::Unavailable,
    };
    transfer(&mut alice_rx, "cancelled by the sender", 30, |t| {
        t.id == offered.id && t.state == unavailable
    })
    .await;
    transfer(&mut bob_rx, "cancelled on the receiver", 30, |t| {
        t.id == offered.id
            && t.state
                == TransferState::Cancelled {
                    by_peer: true,
                    reason: CancelReason::Unavailable,
                }
    })
    .await;
    // The part file is removed by the transfer's worker as it stops.
    let mut left = Vec::new();
    for _ in 0..100 {
        left = std::fs::read_dir(dir.join("bob-downloads"))
            .map(|d| d.map(|e| e.unwrap().file_name()).collect())
            .unwrap_or_default();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(left.is_empty(), "nothing of it is kept: {left:?}");
    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
