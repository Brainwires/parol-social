//! A record corrupted in flight (PNP-010 §6.4). The fault is injected where the sender hands
//! the sealed record to the channel (`test-hooks`): for the receiver that is the same as a
//! change made anywhere on the path. In its own test binary because the hook is global.

mod support;

use parolnet_app::transfer::test_hooks;
use parolnet_app::{CancelReason, TransferState};
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_record_is_refused_and_persistent_tampering_ends_the_transfer() {
    init_tracing();
    let relay = start_relay().await;
    let dir = unique_dir("tamper");
    let ((alice, mut alice_rx), (bob, mut bob_rx)) = paired_pair(&relay, &dir, |_, _| {}).await;
    let source = dir.join("contract.pdf");
    let sha = write_file(&source, 20 * 65_519 + 77);

    // One record in the middle is changed in flight: the receiver refuses it, keeps what
    // came before, and gets the genuine record on a new channel.
    test_hooks::corrupt_records(7, 1);
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    transfer(&mut bob_rx, "the offer", 20, |t| t.id == offered.id).await;
    bob.accept_transfer(&offered.id).await.unwrap();
    let mut cut = false;
    let done = transfer(&mut bob_rx, "the file despite the tampering", 60, |t| {
        if t.id == offered.id && t.state == TransferState::Waiting && t.bytes_done > 0 {
            cut = true;
        }
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;
    assert_eq!(test_hooks::corrupted(), 1, "a record was corrupted");
    assert!(
        cut,
        "the attempt with the bad record ended and the transfer waited"
    );
    let received = done.path.unwrap();
    assert_eq!(
        hash_of(&received),
        sha,
        "no corrupted byte reached the file"
    );
    transfer(&mut alice_rx, "complete", 30, |t| {
        t.id == offered.id && t.state == TransferState::Complete
    })
    .await;
    std::fs::remove_file(&received).unwrap();

    // Every record is changed: after three attempts in a row that end on a bad record the
    // receiver gives up, tells the sender why, and keeps nothing.
    test_hooks::corrupt_records(0, u32::MAX);
    let offered = alice.offer_file(bob.peer_id(), &source).await.unwrap();
    transfer(&mut bob_rx, "the second offer", 20, |t| t.id == offered.id).await;
    bob.accept_transfer(&offered.id).await.unwrap();
    transfer(&mut bob_rx, "given up", 60, |t| {
        t.id == offered.id
            && t.state
                == TransferState::Cancelled {
                    by_peer: false,
                    reason: CancelReason::Integrity,
                }
    })
    .await;
    transfer(&mut alice_rx, "the sender is told", 30, |t| {
        t.id == offered.id
            && t.state
                == TransferState::Cancelled {
                    by_peer: true,
                    reason: CancelReason::Integrity,
                }
    })
    .await;
    // Three attempts, each ended by its first record (the sender may have sealed a few more
    // before it saw the channel close).
    assert!(test_hooks::corrupted() >= 3, "{}", test_hooks::corrupted());
    test_hooks::corrupt_records(0, 0);
    let mut left = Vec::new();
    for _ in 0..100 {
        left = std::fs::read_dir(dir.join("bob-downloads"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        left.is_empty(),
        "nothing of the refused file is kept: {left:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
