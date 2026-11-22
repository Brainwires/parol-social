//! PNP-005 conformance: the mesh node as a whole: store-and-forward (§5.4), the
//! deduplication filter over time (§5.5), set reconciliation (§5.7), peer scoring
//! (§5.8), discovery (§5.9), and what is on disk (§7).
//!
//! The node is a `PeerManager`. Its peers are either other `PeerManager`s in this
//! process or the test itself, which then plays the peer's side of the protocol frame
//! by frame over an in-memory connection.

mod inproc;

use async_trait::async_trait;
use inproc::{
    Draft, PipeEnd, RelayNet, eventually, gossip_frames, identity, now_secs, pipe, pow_zero_bits,
    resign, user_payload,
};
use parolnet_clause::clause;
use parolnet_core::mesh_relay::{
    GossipExit, inject_via_circuit, open_anonymous_user_message, seal_anonymous_user_message,
};
use parolnet_core::{ParolNet, ParolNetConfig};
use parolnet_crypto::SharedSecret;
use parolnet_mesh::clock::Clock;
use parolnet_mesh::connection_pool::{ConnectionPool, PeerOrigin};
use parolnet_mesh::gossip::{
    DedupFilter, GossipParams, Origin, StandardGossip, user_message_dest, verify_anonymous_origin,
};
use parolnet_mesh::mdns::{
    self, MDNS_PORT, MdnsDiscovery, PeerConnector, SERVICE_TYPE, encode_announcement, encode_query,
    parse_packet,
};
use parolnet_mesh::peer_manager::PeerManager;
use parolnet_mesh::reconcile::{GossipIblt, IBLT_CELLS, ID_BATCH, SyncFrame, iblt_key};
use parolnet_mesh::store_forward::{InMemoryStore, MAX_BUFFER_SIZE, MAX_MESSAGES_PER_PEER};
use parolnet_mesh::{DiscoveredPeer, GossipAction, MeshError, MessageStore, PeerDiscovery};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::{GossipEnvelope, GossipPayloadType, PeerAnnouncement};
use parolnet_relay::circuit::StandardCircuitBuilder;
use parolnet_relay::service::ExitHandler;
use parolnet_transport::Connection;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const USER: u8 = GossipPayloadType::UserMessage as u8;
const GROUP: u8 = GossipPayloadType::GroupMetadata as u8;
const ANNOUNCE: u8 = GossipPayloadType::PeerAnnouncement as u8;

fn manager(seed: u8) -> PeerManager {
    let (key, id) = identity(seed);
    PeerManager::new(id, key)
}

/// A peer the test plays: `end` records what the node sends to it.
struct Scripted {
    id: PeerId,
    end: Arc<PipeEnd>,
    far: Arc<PipeEnd>,
}

impl Scripted {
    fn sync_frames(&self) -> Vec<SyncFrame> {
        self.end
            .sent()
            .iter()
            .filter(|f| SyncFrame::is_sync_frame(f))
            .map(|f| SyncFrame::decode(f).unwrap())
            .collect()
    }

    fn gossip(&self) -> Vec<GossipEnvelope> {
        gossip_frames(&self.end)
    }
}

/// Connect a scripted peer to `node`. It is in its sync phase.
async fn connect(node: &PeerManager, seed: u8) -> Scripted {
    connect_as(node, seed, PeerOrigin::Manual).await.unwrap()
}

async fn connect_as(
    node: &PeerManager,
    seed: u8,
    origin: PeerOrigin,
) -> Result<Scripted, MeshError> {
    let (_, id) = identity(seed);
    let (end, far) = pipe();
    node.add_peer_from(id, end.clone(), origin).await?;
    Ok(Scripted { id, end, far })
}

async fn frame(node: &PeerManager, peer: &Scripted, frame: SyncFrame) {
    node.handle_incoming(&peer.id, &frame.encode().unwrap())
        .await
        .unwrap();
}

/// Play a peer that has nothing and wants nothing through its sync phase.
async fn finish_sync(node: &PeerManager, peer: &Scripted) {
    frame(node, peer, SyncFrame::Offer(GossipIblt::new())).await;
    frame(
        node,
        peer,
        SyncFrame::Request {
            keys: vec![],
            ids: vec![],
        },
    )
    .await;
    frame(
        node,
        peer,
        SyncFrame::Data {
            messages: vec![],
            fin: true,
        },
    )
    .await;
    assert!(!node.is_syncing(&peer.id).await);
}

/// Connect a scripted peer and take it through its sync phase: it is ACTIVE.
async fn active_peer(node: &PeerManager, seed: u8) -> Scripted {
    let peer = connect(node, seed).await;
    finish_sync(node, &peer).await;
    peer
}

async fn deliver(
    node: &PeerManager,
    from: &Scripted,
    envelope: &GossipEnvelope,
) -> Result<Option<GossipEnvelope>, MeshError> {
    node.handle_incoming(&from.id, &envelope.to_cbor().unwrap())
        .await
}

async fn after_jitter() {
    tokio::time::sleep(Duration::from_millis(250)).await;
}

/// An envelope for the store tests: no proof of work, no signature, just the fields
/// the store goes by.
fn bare(n: u32, exp: u64, ttl: u8, ts: u64, payload_len: usize) -> GossipEnvelope {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    GossipEnvelope {
        v: 1,
        id: id.to_vec(),
        src: PeerId([7u8; 32]),
        src_pubkey: vec![7u8; 32],
        ts,
        exp,
        ttl,
        hops: 0,
        seen: vec![0u8; 128],
        pow: vec![0u8; 8],
        sig: vec![0u8; 64],
        payload_type: USER,
        payload: vec![0xEE; payload_len],
    }
}

fn number(envelope: &GossipEnvelope) -> u32 {
    u32::from_be_bytes(envelope.id[..4].try_into().unwrap())
}

// ── §3.5 Anonymous user messages, end to end ──────────────────

#[clause(
    "PNP-005-MUST-007",
    "PNP-005-MUST-008",
    "PNP-005-SHOULD-001",
    "PNP-005-SHOULD-013"
)]
#[tokio::test(start_paused = true)]
async fn an_anonymous_user_message_names_its_sender_only_inside_the_encrypted_payload() {
    // Alice and Bob have a Double Ratchet session.
    let alice = ParolNet::new(ParolNetConfig::default());
    let bob = ParolNet::new(ParolNetConfig::default());
    let bob_ratchet = [0x44u8; 32];
    let bob_ratchet_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_ratchet)).to_bytes();
    alice
        .establish_session(
            bob.peer_id(),
            SharedSecret([0x33; 32]),
            &bob_ratchet_public,
            true,
        )
        .unwrap();
    bob.establish_responder_session(alice.peer_id(), SharedSecret([0x33; 32]), bob_ratchet)
        .unwrap();

    let alice_key = ed25519_dalek::SigningKey::from_bytes(&alice.export_identity_secret());
    let alice_public = alice_key.verifying_key().to_bytes();
    assert_eq!(PeerId::from_public_key(&alice_public), alice.peer_id());
    let alice_gossip =
        StandardGossip::new(alice.peer_id(), alice_key, Arc::new(ConnectionPool::new()));

    let envelope = seal_anonymous_user_message(
        alice.sessions(),
        &alice_gossip,
        &bob.peer_id(),
        b"meet at noon",
        now_secs(),
    )
    .unwrap();

    // On the wire: no source, no key, and neither Alice's PeerId nor her key anywhere
    // in the bytes. The message is not readable there either.
    assert!(envelope.is_anonymous());
    let wire = envelope.to_cbor().unwrap();
    assert!(!wire.windows(32).any(|w| w == alice.peer_id().0));
    assert!(!wire.windows(32).any(|w| w == alice_public));
    assert!(!wire.windows(12).any(|w| w == b"meet at noon"));
    // A relaying node takes it and passes it on, learning only whom it is for.
    let relay = manager(50);
    let next = active_peer(&relay, 51).await;
    assert!(relay.inject(&wire).await.unwrap().is_none());
    after_jitter().await;
    let relayed = next.gossip().pop().expect("the relay forwarded it");
    assert_eq!(user_message_dest(&relayed.payload), Some(bob.peer_id()));
    // (The payload is a whole PNP-001 envelope. Reading a bare cleartext header off its
    // start, as the node once did to find the destination, finds nothing.)
    assert!(
        ciborium::from_reader::<parolnet_protocol::envelope::CleartextHeader, _>(
            relayed.payload.as_slice()
        )
        .is_err()
    );

    // Bob's own node recognises the message as his (the destination in the PNP-001
    // header) and hands it to the application.
    let bob_node = PeerManager::new(
        bob.peer_id(),
        ed25519_dalek::SigningKey::from_bytes(&bob.export_identity_secret()),
    );
    let relayed = bob_node
        .inject(&relayed.to_cbor().unwrap())
        .await
        .unwrap()
        .expect("delivered to the node it is addressed to");

    // MUST-007: Bob decrypts, and inside is who sent it. MUST-008: the envelope's
    // signature verifies with the key found there.
    let (sender, body) = open_anonymous_user_message(bob.sessions(), &relayed).unwrap();
    assert_eq!(sender, alice.peer_id());
    assert_eq!(body, b"meet at noon");
    assert!(verify_anonymous_origin(&relayed, &alice_public).is_ok());
    // The signature is over the zeroed src and the empty key: put Alice's real ones in
    // and it no longer holds.
    let mut named = relayed.clone();
    named.src = alice.peer_id();
    named.src_pubkey = alice_public.to_vec();
    assert!(matches!(
        manager(52).inject(&named.to_cbor().unwrap()).await,
        Err(MeshError::InvalidSignature)
    ));

    // An envelope carrying Alice's ciphertext under someone else's signature (a relay
    // re-wrapping her message) is refused by Bob, and his session is none the worse:
    // the genuine envelope still opens.
    let second = seal_anonymous_user_message(
        alice.sessions(),
        &alice_gossip,
        &bob.peer_id(),
        b"second message",
        now_secs(),
    )
    .unwrap();
    let mut rewrapped = second.clone();
    resign(&mut rewrapped, &identity(66).0);
    assert!(open_anonymous_user_message(bob.sessions(), &rewrapped).is_err());
    let mut altered = second.clone();
    altered.exp -= 1;
    assert!(open_anonymous_user_message(bob.sessions(), &altered).is_err());
    let (sender, body) = open_anonymous_user_message(bob.sessions(), &second).unwrap();
    assert_eq!(
        (sender, body.as_slice()),
        (alice.peer_id(), &b"second message"[..])
    );
}

// ── §5.4 Store-and-forward ────────────────────────────────────

#[clause("PNP-005-MUST-029")]
#[tokio::test]
async fn a_peer_buffer_never_exceeds_256_messages_or_4_mb() {
    let now = now_secs();
    let peer = PeerId([1; 32]);
    assert_eq!(
        (MAX_MESSAGES_PER_PEER, MAX_BUFFER_SIZE),
        (256, 4 * 1024 * 1024)
    );

    // By count.
    let store = InMemoryStore::new();
    for n in 0..300u32 {
        store
            .store(&peer, &bare(n, now + 1000 + n as u64, 7, now, 100))
            .await
            .unwrap();
        assert!(store.count_for_peer(&peer).await <= 256);
    }
    assert_eq!(store.count_for_peer(&peer).await, 256);

    // By size, well before 256 messages: 60 kB each.
    let store = InMemoryStore::new();
    let mut most = 0;
    for n in 0..120u32 {
        store
            .store(&peer, &bare(n, now + 1000 + n as u64, 7, now, 60_000))
            .await
            .unwrap();
        let bytes = store.bytes_for_peer(&peer).await;
        assert!(
            bytes <= MAX_BUFFER_SIZE,
            "{bytes} bytes buffered after {n} messages"
        );
        most = most.max(bytes);
    }
    let count = store.count_for_peer(&peer).await;
    assert!(count < 80 && count > 60, "{count} messages of 60 kB");
    assert!(most > MAX_BUFFER_SIZE - 70_000, "the buffer never filled");
    // One message of the maximum payload size after another: still within 4 MB.
    for n in 0..80u32 {
        store
            .store(&peer, &bare(1000 + n, now + 5000, 7, now, 65_536))
            .await
            .unwrap();
        assert!(store.bytes_for_peer(&peer).await <= MAX_BUFFER_SIZE);
    }
    // The bound is per peer.
    let other = PeerId([2; 32]);
    store
        .store(&other, &bare(1, now + 1000, 7, now, 60_000))
        .await
        .unwrap();
    assert_eq!(store.count_for_peer(&other).await, 1);
}

#[clause("PNP-005-MUST-030")]
#[tokio::test]
async fn a_full_buffer_evicts_by_expiry_then_ttl_then_age() {
    let now = now_secs();
    let peer = PeerId([1; 32]);
    let remaining = |store: InMemoryStore| async move {
        let left: HashSet<u32> = store
            .retrieve(&peer)
            .await
            .unwrap()
            .iter()
            .map(number)
            .collect();
        left
    };

    // a. Nearest expiry goes first, whatever its TTL and age.
    let store = InMemoryStore::new();
    for n in 0..256u32 {
        let (exp, ttl, ts) = match n {
            100 => (now + 500, 15, now),    // soonest to expire, highest TTL, newest
            _ => (now + 9000, 1, now - 50), // later expiry, lowest TTL, older
        };
        store
            .store(&peer, &bare(n, exp, ttl, ts, 10))
            .await
            .unwrap();
    }
    store
        .store(&peer, &bare(999, now + 9000, 7, now, 10))
        .await
        .unwrap();
    let left = remaining(store).await;
    assert_eq!(left.len(), 256);
    assert!(
        !left.contains(&100),
        "the message nearest its expiry was kept"
    );
    assert!(left.contains(&999));

    // b. Expiry equal: lowest remaining TTL goes first, whatever its age.
    let store = InMemoryStore::new();
    for n in 0..256u32 {
        let (ttl, ts) = if n == 42 { (2, now) } else { (9, now - 100) };
        store
            .store(&peer, &bare(n, now + 9000, ttl, ts, 10))
            .await
            .unwrap();
    }
    store
        .store(&peer, &bare(999, now + 9000, 9, now, 10))
        .await
        .unwrap();
    let left = remaining(store).await;
    assert!(
        !left.contains(&42),
        "the message with the lowest TTL was kept"
    );
    assert_eq!(left.len(), 256);

    // c. Expiry and TTL equal: the oldest by origination timestamp goes first, not the
    //    one that happened to be stored first.
    let store = InMemoryStore::new();
    for n in 0..256u32 {
        let ts = if n == 200 {
            now - 5000
        } else {
            now - 100 + (n as u64 % 50)
        };
        store
            .store(&peer, &bare(n, now + 9000, 9, ts, 10))
            .await
            .unwrap();
    }
    store
        .store(&peer, &bare(999, now + 9000, 9, now, 10))
        .await
        .unwrap();
    let left = remaining(store).await;
    assert!(!left.contains(&200), "the oldest message was kept");
    assert!(
        left.contains(&0),
        "the first stored was evicted instead of the oldest"
    );
    assert_eq!(left.len(), 256);

    // The order holds over many evictions: 256 messages with distinct expiries, then
    // 100 more with late expiries, push out exactly the 100 nearest their expiry.
    let store = InMemoryStore::new();
    for n in 0..256u32 {
        // Stored in an order unrelated to expiry.
        let exp = now + 1000 + ((n * 97) % 256) as u64;
        store.store(&peer, &bare(n, exp, 7, now, 10)).await.unwrap();
    }
    for n in 0..100u32 {
        store
            .store(&peer, &bare(5000 + n, now + 50_000, 7, now, 10))
            .await
            .unwrap();
    }
    let left = remaining(store).await;
    for n in 0..256u32 {
        let rank = (n * 97) % 256;
        assert_eq!(
            left.contains(&n),
            rank >= 100,
            "message with expiry rank {rank}"
        );
    }
}

#[clause("PNP-005-MUST-031", "PNP-005-SHOULD-004")]
#[tokio::test(start_paused = true)]
async fn messages_for_a_disconnected_peer_are_buffered_and_delivered_after_its_sync() {
    let node = manager(1);
    let feeder = active_peer(&node, 2).await;
    // Bob has been connected and has gone away.
    let bob = active_peer(&node, 3).await;
    node.remove_peer(&bob.id).await;

    // SHOULD-004: a message for Bob that passes through is kept for him.
    let for_bob = Draft::new(&identity(9).0)
        .payload(user_payload(bob.id, b"while you were out"))
        .build();
    deliver(&node, &feeder, &for_bob).await.unwrap();
    assert_eq!(node.store().count_for_peer(&bob.id).await, 1);
    // Not one for a peer this node has never known, nor one for a peer that is here.
    let stranger = identity(77).1;
    let for_stranger = Draft::new(&identity(10).0)
        .payload(user_payload(stranger, b"x"))
        .build();
    deliver(&node, &feeder, &for_stranger).await.unwrap();
    let carol = active_peer(&node, 4).await;
    let for_carol = Draft::new(&identity(11).0)
        .payload(user_payload(carol.id, b"x"))
        .build();
    deliver(&node, &feeder, &for_carol).await.unwrap();
    assert_eq!(node.store().total_count().await, 1);

    // Bob reconnects. First comes the sync offer; the buffered message waits.
    let bob = connect(&node, 3).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(matches!(bob.sync_frames()[..], [SyncFrame::Offer(_)]));
    assert!(bob.gossip().is_empty(), "delivered before the sync phase");

    // Bob (who holds nothing and asks for nothing) goes through the sync.
    finish_sync(&node, &bob).await;
    // MUST-031: now the buffered message is delivered, after every sync frame.
    let sent = bob.end.sent();
    let delivered = bob.gossip();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, for_bob.id);
    assert_eq!(delivered[0].ttl, for_bob.ttl - 1);
    let last_sync = sent
        .iter()
        .rposition(|f| SyncFrame::is_sync_frame(f))
        .unwrap();
    let first_gossip = sent
        .iter()
        .position(|f| !SyncFrame::is_sync_frame(f))
        .unwrap();
    assert!(first_gossip > last_sync);
    assert_eq!(node.store().count_for_peer(&bob.id).await, 0);

    // "To avoid duplicates": what Bob already got through the sync is not sent again.
    node.remove_peer(&bob.id).await;
    let again = Draft::new(&identity(12).0)
        .payload(user_payload(bob.id, b"second"))
        .build();
    deliver(&node, &feeder, &again).await.unwrap();
    assert_eq!(node.store().count_for_peer(&bob.id).await, 1);
    let bob = connect(&node, 3).await;
    frame(&node, &bob, SyncFrame::Offer(GossipIblt::new())).await;
    // This time Bob asks for it in the sync.
    let wanted = iblt_key(&again.message_id().unwrap());
    frame(
        &node,
        &bob,
        SyncFrame::Request {
            keys: vec![wanted],
            ids: vec![],
        },
    )
    .await;
    frame(
        &node,
        &bob,
        SyncFrame::Data {
            messages: vec![],
            fin: true,
        },
    )
    .await;
    assert!(!node.is_syncing(&bob.id).await);
    let in_sync: Vec<Vec<u8>> = bob
        .sync_frames()
        .into_iter()
        .filter_map(|f| match f {
            SyncFrame::Data { messages, .. } => Some(messages),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        in_sync
            .iter()
            .any(|m| GossipEnvelope::decode_unvalidated(m).unwrap().id == again.id)
    );
    assert!(
        bob.gossip().is_empty(),
        "sent in the sync and again after it"
    );
}

#[clause("PNP-005-MUST-032")]
#[tokio::test(start_paused = true)]
async fn expired_messages_leave_the_buffer_within_a_minute_without_being_asked() {
    let (key, id) = identity(1);
    let start = now_secs();
    let node = PeerManager::with_clock(id, key, Clock::following_tokio(start));
    let feeder = active_peer(&node, 2).await;
    let bob = active_peer(&node, 3).await;
    node.remove_peer(&bob.id).await;

    // Two messages for Bob: one with 100 seconds to live, one with a day.
    let short = Draft::new(&identity(9).0)
        .ts(start)
        .lifetime(100)
        .payload(user_payload(bob.id, b"short-lived"))
        .build();
    let long = Draft::new(&identity(10).0)
        .ts(start)
        .payload(user_payload(bob.id, b"long-lived"))
        .build();
    deliver(&node, &feeder, &short).await.unwrap();
    deliver(&node, &feeder, &long).await.unwrap();
    assert_eq!(node.store().count_for_peer(&bob.id).await, 2);

    // Alive at 95 seconds, housekeeping or not.
    tokio::time::sleep(Duration::from_secs(95)).await;
    assert_eq!(node.store().count_for_peer(&bob.id).await, 2);
    // It expires at 100 s. Nobody calls expire(); within 60 seconds it is gone.
    tokio::time::sleep(Duration::from_secs(65)).await;
    assert_eq!(
        node.store().count_for_peer(&bob.id).await,
        1,
        "still buffered 60 s after expiry"
    );
    // The one that is left is the long-lived one.
    let bob = connect(&node, 3).await;
    finish_sync(&node, &bob).await;
    let delivered = bob.gossip();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, long.id);
}

// ── §5.5 Deduplication filter ─────────────────────────────────

#[clause("PNP-005-MUST-034")]
#[tokio::test(start_paused = true)]
async fn the_deduplication_filter_rotates_every_12_hours() {
    let filter = DedupFilter::new();
    let early = [1u8; 32];
    filter.mark_seen(early);

    // Within the first 12 hours it is in "current".
    tokio::time::sleep(Duration::from_secs(11 * 3600)).await;
    assert!(filter.is_seen(&early));
    let late = [2u8; 32];
    filter.mark_seen(late);
    // After the first rotation it is in "previous": still seen.
    tokio::time::sleep(Duration::from_secs(2 * 3600)).await;
    assert!(filter.is_seen(&early));
    assert!(filter.is_seen(&late));
    // After the second, "previous" was discarded. Nothing called rotate().
    tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
    assert!(
        !filter.is_seen(&early),
        "an ID from 25 hours ago is still held"
    );
    assert!(!filter.is_seen(&late));

    // On a node: a message is a duplicate for as long as the filter holds it, and the
    // node forgets it afterwards without anyone running maintenance.
    let (key, id) = identity(1);
    let start = now_secs();
    let node = PeerManager::with_clock(id, key, Clock::following_tokio(start));
    let message = Draft::new(&identity(9).0)
        .ts(start)
        .payload_type(GROUP)
        .build();
    let wire = message.to_cbor().unwrap();
    assert!(node.inject(&wire).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_secs(13 * 3600)).await;
    assert!(
        node.inject(&wire).await.unwrap().is_none(),
        "not recognised after one rotation"
    );
    assert!(node.gossip().dedup.is_seen(&message.message_id().unwrap()));
    tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
    assert!(!node.gossip().dedup.is_seen(&message.message_id().unwrap()));
}

#[clause("PNP-005-SHOULD-005")]
#[test]
fn the_deduplication_filter_holds_100_000_ids_at_under_one_false_positive_in_a_thousand() {
    let id_of = |n: u32, salt: u8| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([salt]);
        h.update(n.to_be_bytes());
        h.finalize().into()
    };
    let filter = DedupFilter::new();
    for n in 0..100_000u32 {
        filter.mark_seen(id_of(n, 1));
    }
    // Everything inserted is found.
    for n in (0..100_000u32).step_by(7) {
        assert!(filter.is_seen(&id_of(n, 1)), "id {n} lost");
    }
    // Of 100,000 IDs never inserted, at most 0.1% are mistaken for seen.
    let false_positives = (0..100_000u32)
        .filter(|n| filter.is_seen(&id_of(*n, 2)))
        .count();
    assert!(
        false_positives <= 100,
        "{false_positives} false positives in 100,000"
    );

    // Still so with both halves of the double buffer full.
    for n in 0..100_000u32 {
        filter.mark_seen(id_of(n, 3));
    }
    assert!(filter.is_seen(&id_of(0, 1)) && filter.is_seen(&id_of(0, 3)));
    let false_positives = (0..100_000u32)
        .filter(|n| filter.is_seen(&id_of(*n, 4)))
        .count();
    assert!(
        false_positives <= 100,
        "{false_positives} false positives with both filters full"
    );
}

// ── §5.7 Sync ─────────────────────────────────────────────────

#[clause("PNP-005-MUST-039")]
#[test]
fn the_iblt_has_the_pinned_parameters_and_encoding() {
    use ciborium::value::Value;
    let id = [0xABu8; 32];
    let iblt = GossipIblt::from_ids([&id]);
    assert_eq!(iblt.num_cells(), 1024);
    assert_eq!(IBLT_CELLS, 1024);
    assert_eq!(iblt.num_hashes(), 3);

    // The key is the first 8 bytes of SHA-256(message ID); the cell's check value the
    // first 4 bytes of SHA-256(key).
    let key = u64::from_be_bytes(Sha256::digest(id)[..8].try_into().unwrap());
    assert_eq!(iblt_key(&id), key);
    let check = u32::from_be_bytes(Sha256::digest(key.to_be_bytes())[..4].try_into().unwrap());

    // Encoding: a CBOR array of 1024 maps {"c": int, "k": uint, "h": uint}.
    let decoded: Value = ciborium::from_reader(iblt.to_cbor().unwrap().as_slice()).unwrap();
    let cells = decoded.as_array().expect("an array");
    assert_eq!(cells.len(), 1024);
    let mut occupied = 0;
    for cell in cells {
        let map = cell.as_map().expect("each cell is a map");
        let mut keys: Vec<&str> = map.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["c", "h", "k"]);
        let get = |name: &str| -> i128 {
            let value = &map
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .unwrap()
                .1;
            value.as_integer().expect("an integer").into()
        };
        if get("c") != 0 {
            occupied += 1;
            // count 1, keySum the key, hashSum its check.
            assert_eq!(get("c"), 1);
            assert_eq!(get("k"), key as i128);
            assert_eq!(get("h"), check as i128);
        } else {
            assert_eq!((get("k"), get("h")), (0, 0));
        }
    }
    // Three hash functions: the one entry sits in three cells.
    assert_eq!(occupied, 3);

    // It does its job: two sets that differ in 500 IDs are told apart exactly.
    let ids: Vec<[u8; 32]> = (0..1200u32)
        .map(|n| Sha256::digest(n.to_be_bytes()).into())
        .collect();
    let mine = GossipIblt::from_ids(ids[..600].iter());
    let theirs = GossipIblt::from_ids(ids[300..800].iter());
    let mut diff = GossipIblt::from_cbor(&mine.to_cbor().unwrap()).unwrap();
    diff.subtract(&theirs);
    let (only_mine, only_theirs) = diff.decode().expect("500 differences decode");
    let expect_mine: HashSet<u64> = ids[..300].iter().map(iblt_key).collect();
    let expect_theirs: HashSet<u64> = ids[600..800].iter().map(iblt_key).collect();
    assert_eq!(only_mine.into_iter().collect::<HashSet<_>>(), expect_mine);
    assert_eq!(
        only_theirs.into_iter().collect::<HashSet<_>>(),
        expect_theirs
    );
    // When the difference is too large for 1024 cells the decode says so; it does not
    // return a partial answer. (That is the signal for the full-list fallback.)
    let mut too_many = GossipIblt::from_ids(ids[..100].iter());
    too_many.subtract(&GossipIblt::from_ids(ids[100..].iter()));
    assert!(too_many.decode().is_err());
    // A table of another size is not accepted.
    let mut short = Vec::new();
    ciborium::into_writer(&cells[..1000].to_vec(), &mut short).unwrap();
    assert!(GossipIblt::from_cbor(&short).is_err());
}

#[clause("PNP-005-MUST-038")]
#[tokio::test(start_paused = true)]
async fn two_peers_reconcile_their_message_sets_when_they_connect() {
    let a = manager(1);
    let b = manager(2);
    // A holds three messages B lacks, B one that A lacks, and both hold one in common.
    let make = |seed: u8| Draft::new(&identity(seed).0).payload_type(GROUP).build();
    let only_a: Vec<GossipEnvelope> = (10..13).map(make).collect();
    let only_b = make(20);
    let common = make(30);
    for m in only_a.iter().chain([&common]) {
        a.inject(&m.to_cbor().unwrap()).await.unwrap();
    }
    for m in [&only_b, &common] {
        b.inject(&m.to_cbor().unwrap()).await.unwrap();
    }
    let mut b_got = b.subscribe();

    let (a_end, b_end) = pipe();
    {
        let (a, b) = (a.clone(), b.clone());
        let (a_id, b_id) = (a.peer_id(), b.peer_id());
        let (a_conn, b_conn) = (a_end.clone(), b_end.clone());
        tokio::spawn(async move { a.run_peer(b_id, a_conn).await });
        tokio::spawn(async move { b.run_peer(a_id, b_conn).await });
    }
    let (a2, b2) = (a.clone(), b.clone());
    eventually(Duration::from_secs(5), "both sets to be equal", move || {
        a2.gossip().cached_ids().len() == 5 && b2.gossip().cached_ids().len() == 5
    })
    .await;

    // Each now holds all five.
    let all: HashSet<Vec<u8>> = only_a
        .iter()
        .chain([&only_b, &common])
        .map(|m| m.id.clone())
        .collect();
    for node in [&a, &b] {
        let held: HashSet<Vec<u8>> = node
            .gossip()
            .cached_ids()
            .iter()
            .map(|id| id.to_vec())
            .collect();
        assert_eq!(held, all);
    }
    // What B got, it got as gossip messages it validated and delivered.
    let mut delivered = HashSet::new();
    while let Ok(m) = b_got.try_recv() {
        delivered.insert(m.id);
    }
    assert_eq!(delivered, only_a.iter().map(|m| m.id.clone()).collect());

    // On the wire: each side opened with its IBLT, asked for exactly what it lacked,
    // and was sent exactly that. The common message never moved.
    let frames = |end: &PipeEnd| -> Vec<SyncFrame> {
        end.sent()
            .iter()
            .filter(|f| SyncFrame::is_sync_frame(f))
            .map(|f| SyncFrame::decode(f).unwrap())
            .collect()
    };
    let (from_a, from_b) = (frames(&a_end), frames(&b_end));
    for side in [&from_a, &from_b] {
        assert!(
            matches!(side[0], SyncFrame::Offer(_)),
            "the first frame is not SYNC_OFFER"
        );
    }
    let asked = |side: &[SyncFrame]| -> Vec<u64> {
        side.iter()
            .find_map(|f| match f {
                SyncFrame::Request { keys, .. } => Some(keys.clone()),
                _ => None,
            })
            .expect("a SYNC_REQUEST")
    };
    assert_eq!(
        asked(&from_a),
        vec![iblt_key(&only_b.message_id().unwrap())]
    );
    assert_eq!(
        asked(&from_b).into_iter().collect::<HashSet<_>>(),
        only_a
            .iter()
            .map(|m| iblt_key(&m.message_id().unwrap()))
            .collect()
    );
    let sent = |side: &[SyncFrame]| -> usize {
        side.iter()
            .map(|f| match f {
                SyncFrame::Data { messages, .. } => messages.len(),
                _ => 0,
            })
            .sum()
    };
    assert_eq!((sent(&from_a), sent(&from_b)), (3, 1));
    // Both are past the sync phase.
    assert!(!a.is_syncing(&b.peer_id()).await && !b.is_syncing(&a.peer_id()).await);
    assert!(a.pool().is_active(&b.peer_id()).await);
}

#[clause("PNP-005-SHOULD-007")]
#[tokio::test(start_paused = true)]
async fn when_the_iblt_cannot_decode_peers_exchange_full_id_lists_500_at_a_time() {
    assert_eq!(ID_BATCH, 500);
    // The batching itself.
    let ids: Vec<[u8; 32]> = (0..1201u32)
        .map(|n| Sha256::digest(n.to_be_bytes()).into())
        .collect();
    let batches = SyncFrame::id_batches(&ids);
    let sizes: Vec<(usize, bool)> = batches
        .iter()
        .map(|f| match f {
            SyncFrame::Ids { ids, fin } => (ids.len(), *fin),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sizes, vec![(500, false), (500, false), (201, true)]);
    // A frame of more than 500 is not accepted.
    let oversized = SyncFrame::Ids {
        ids: ids[..501].to_vec(),
        fin: true,
    }
    .encode()
    .unwrap();
    assert!(SyncFrame::decode(&oversized).is_err());

    // A node holding three messages meets a peer whose set differs by 1201.
    let node = manager(1);
    let held: Vec<GossipEnvelope> = (10..13)
        .map(|seed| Draft::new(&identity(seed).0).payload_type(GROUP).build())
        .collect();
    for m in &held {
        node.inject(&m.to_cbor().unwrap()).await.unwrap();
    }
    let peer = connect(&node, 2).await;
    frame(
        &node,
        &peer,
        SyncFrame::Offer(GossipIblt::from_ids(ids.iter())),
    )
    .await;
    // The table cannot be decoded, so the node does not ask by key: it sends its own
    // full list.
    let answer = peer.sync_frames();
    assert!(
        !answer
            .iter()
            .any(|f| matches!(f, SyncFrame::Request { .. }))
    );
    match &answer[1] {
        SyncFrame::Ids { ids, fin } => {
            let mine: HashSet<[u8; 32]> = ids.iter().copied().collect();
            assert_eq!(mine, held.iter().map(|m| m.message_id().unwrap()).collect());
            assert!(fin);
        }
        other => panic!("{other:?}"),
    }
    // The peer sends its list in batches; after the last one the node asks, by full
    // ID, for everything in it that it lacks.
    for batch in batches {
        frame(&node, &peer, batch).await;
    }
    let request = peer
        .sync_frames()
        .into_iter()
        .find_map(|f| match f {
            SyncFrame::Request { keys, ids } => Some((keys, ids)),
            _ => None,
        })
        .expect("a request after the lists");
    assert!(request.0.is_empty());
    assert_eq!(request.1.len(), 1201);
    assert_eq!(
        request.1.into_iter().collect::<HashSet<_>>(),
        ids.iter().copied().collect()
    );
    // And it serves the peer's request by ID the same way.
    let wanted: Vec<[u8; 32]> = held.iter().map(|m| m.message_id().unwrap()).collect();
    frame(
        &node,
        &peer,
        SyncFrame::Request {
            keys: vec![],
            ids: wanted,
        },
    )
    .await;
    frame(
        &node,
        &peer,
        SyncFrame::Data {
            messages: vec![],
            fin: true,
        },
    )
    .await;
    let served: usize = peer
        .sync_frames()
        .iter()
        .map(|f| match f {
            SyncFrame::Data { messages, .. } => messages.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(served, 3);
    assert!(!node.is_syncing(&peer.id).await);
    // The sync is over: asking again gets nothing more.
    let frames_so_far = peer.end.sent().len();
    let wanted: Vec<[u8; 32]> = held.iter().map(|m| m.message_id().unwrap()).collect();
    frame(
        &node,
        &peer,
        SyncFrame::Request {
            keys: vec![],
            ids: wanted,
        },
    )
    .await;
    assert_eq!(peer.end.sent().len(), frames_so_far);
}

#[clause("PNP-005-MUST-040", "PNP-005-MUST-041")]
#[tokio::test(start_paused = true)]
async fn a_sync_that_does_not_finish_in_30_seconds_is_over_and_the_peer_is_active() {
    let node = manager(1);
    let feeder = active_peer(&node, 2).await;
    // Bob has a message waiting, reconnects, and then says nothing at all.
    let bob = active_peer(&node, 3).await;
    node.remove_peer(&bob.id).await;
    let waiting = Draft::new(&identity(9).0)
        .payload(user_payload(bob.id, b"waiting"))
        .build();
    deliver(&node, &feeder, &waiting).await.unwrap();
    let bob = connect(&node, 3).await;

    // During the sync phase Bob is not part of gossip forwarding.
    tokio::time::sleep(Duration::from_secs(10)).await;
    deliver(&node, &feeder, &Draft::new(&identity(10).0).build())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(19)).await;
    assert!(
        node.is_syncing(&bob.id).await,
        "the sync phase ended before 30 s"
    );
    assert!(bob.gossip().is_empty());

    // MUST-040: at 30 seconds it is over.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!node.is_syncing(&bob.id).await, "still syncing after 30 s");
    // MUST-041: Bob is ACTIVE. What was buffered for him is delivered...
    assert!(node.pool().is_active(&bob.id).await);
    let delivered = bob.gossip();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, waiting.id);
    // ...gossip reaches him...
    let fresh = Draft::new(&identity(11).0).build();
    deliver(&node, &feeder, &fresh).await.unwrap();
    after_jitter().await;
    assert!(bob.gossip().iter().any(|m| m.id == fresh.id));
    // ...and a message that crosses twice because the sets were never compared is
    // absorbed by deduplication: no error, no second delivery, not forwarded again.
    let before = feeder.gossip().len();
    let outcome = deliver(&node, &bob, &fresh).await;
    assert!(matches!(outcome, Ok(None)));
    after_jitter().await;
    assert_eq!(feeder.gossip().len(), before);

    // A sync that does finish ends the phase at once, not at 30 seconds.
    let carol = connect(&node, 4).await;
    finish_sync(&node, &carol).await;
    assert!(node.pool().is_active(&carol.id).await);
}

// ── §5.8 Peer scoring ─────────────────────────────────────────

#[clause("PNP-005-SHOULD-008", "PNP-005-SHOULD-010")]
#[tokio::test(start_paused = true)]
async fn a_peer_starts_at_100_and_its_score_drifts_back_one_point_an_hour() {
    let (key, id) = identity(1);
    let start = now_secs();
    let node = PeerManager::with_clock(id, key, Clock::following_tokio(start));
    let peer = active_peer(&node, 2).await;
    let score = || async { node.pool().get_score(&peer.id).await.unwrap().score };

    // SHOULD-008: initialized to 100.
    assert_eq!(score().await, 100);
    // +1 for a valid new message, -1 for a duplicate, -2 for an expired one, -10 for
    // an invalid one.
    let valid = Draft::new(&identity(9).0).ts(start).build();
    deliver(&node, &peer, &valid).await.unwrap();
    assert_eq!(score().await, 101);
    deliver(&node, &peer, &valid).await.unwrap();
    assert_eq!(score().await, 100);
    let expired = Draft::new(&identity(10).0)
        .ts(start - 500)
        .lifetime(100)
        .build();
    assert!(deliver(&node, &peer, &expired).await.is_err());
    assert_eq!(score().await, 98);
    let mut forged = Draft::new(&identity(11).0).ts(start).difficulty(0).build();
    forged.sig = vec![0; 64];
    assert!(deliver(&node, &peer, &forged).await.is_err());
    assert_eq!(score().await, 88);

    // SHOULD-010: one point an hour towards 100, and no further.
    tokio::time::sleep(Duration::from_secs(3600 + 1)).await;
    assert_eq!(score().await, 89);
    tokio::time::sleep(Duration::from_secs(5 * 3600)).await;
    assert_eq!(score().await, 94);
    tokio::time::sleep(Duration::from_secs(48 * 3600)).await;
    assert_eq!(score().await, 100);

    // From above too: twelve valid messages, then hours.
    for seed in 20..32u8 {
        let now = start + 54 * 3600 + 1;
        let m = Draft::new(&identity(seed).0).ts(now).build();
        deliver(&node, &peer, &m).await.unwrap();
    }
    assert_eq!(score().await, 112);
    tokio::time::sleep(Duration::from_secs(3 * 3600)).await;
    assert_eq!(score().await, 109);
    tokio::time::sleep(Duration::from_secs(40 * 3600)).await;
    assert_eq!(score().await, 100);
}

#[clause("PNP-005-SHOULD-009")]
#[tokio::test(start_paused = true)]
async fn a_peer_whose_score_falls_below_zero_is_disconnected_and_refused_for_an_hour() {
    let node = manager(1);
    let peer = active_peer(&node, 2).await;
    let other = active_peer(&node, 3).await;

    // Ten invalid messages: the score is 0, which is not below 0.
    let forged = || {
        let mut e = Draft::new(&identity(9).0).difficulty(0).build();
        e.sig = vec![0; 64];
        e
    };
    for _ in 0..10 {
        assert!(deliver(&node, &peer, &forged()).await.is_err());
    }
    assert_eq!(node.pool().get_score(&peer.id).await.unwrap().score, 0);
    assert!(node.pool().is_connected(&peer.id).await);
    // The eleventh takes it below.
    assert!(deliver(&node, &peer, &forged()).await.is_err());
    assert!(
        !node.pool().is_connected(&peer.id).await,
        "still connected at -10"
    );
    assert_eq!(node.peer_count().await, 1);
    // Its connection was closed: the other end reads what was sent and then the end.
    let closed = tokio::time::timeout(Duration::from_secs(1), async {
        while peer.far.recv().await.is_ok() {}
    })
    .await;
    assert!(closed.is_ok(), "the connection was left open");
    // Gossip no longer goes to it.
    deliver(&node, &other, &Draft::new(&identity(10).0).build())
        .await
        .unwrap();
    after_jitter().await;
    assert!(peer.gossip().is_empty());

    // Reconnection is refused for an hour.
    for wait in [0u64, 30 * 60, 29 * 60] {
        tokio::time::sleep(Duration::from_secs(wait)).await;
        assert!(matches!(
            connect_as(&node, 2, PeerOrigin::Manual).await,
            Err(MeshError::PeerBanned)
        ));
    }
    // And accepted after it, with a clean slate.
    tokio::time::sleep(Duration::from_secs(61)).await;
    let back = connect(&node, 2).await;
    assert!(node.pool().is_connected(&back.id).await);
    assert_eq!(node.pool().get_score(&back.id).await.unwrap().score, 100);
}

// ── §5.9 Discovery ────────────────────────────────────────────

#[clause("PNP-005-MUST-042")]
#[test]
fn the_mdns_announcement_is_for_parolnet_tcp_local_with_the_peer_id_in_txt() {
    assert_eq!(SERVICE_TYPE, "_parolnet._tcp.local.");
    assert_eq!(MDNS_PORT, 5353);
    assert_eq!(mdns::MDNS_GROUP, std::net::Ipv4Addr::new(224, 0, 0, 251));
    let (_, id) = identity(7);
    let hex_id: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
    let packet = encode_announcement(&id, 9443);

    // A DNS response (QR and AA set) with no question.
    assert_eq!(packet[2] & 0x80, 0x80);
    assert_eq!(&packet[4..6], &[0, 0]);
    // The service type, as DNS labels.
    let service = b"\x09_parolnet\x04_tcp\x05local\x00";
    assert!(packet.windows(service.len()).any(|w| w == service));
    // A TXT record holding the PeerId in hex.
    let txt = format!("peerid={hex_id}");
    assert!(packet.windows(txt.len()).any(|w| w == txt.as_bytes()));
    assert_eq!(hex_id.len(), 64);

    // Read back by the listening side: the PeerId and the port to connect to.
    let parsed = parse_packet(&packet).unwrap();
    assert_eq!(parsed.peers, vec![(id, 9443)]);
    assert!(!parsed.asks_for_service);
    // The question nodes ask each other is for the same service type.
    let query = encode_query();
    assert!(query.windows(service.len()).any(|w| w == service));
    let parsed = parse_packet(&query).unwrap();
    assert!(parsed.asks_for_service);
    assert!(parsed.peers.is_empty());
    // Other services' records and broken packets yield no peers.
    let mut other = packet.clone();
    while let Some(at) = other.windows(9).position(|w| w == b"_parolnet") {
        other[at + 1] = b'q';
    }
    assert!(parse_packet(&other).is_none_or(|p| p.peers.is_empty()));
    assert!(parse_packet(&packet[..20]).is_none_or(|p| p.peers.is_empty()));
    assert!(parse_packet(&[0u8; 5]).is_none());
}

struct Recorder {
    found: Mutex<Vec<DiscoveredPeer>>,
}

#[async_trait]
impl PeerConnector for Recorder {
    async fn connect(&self, peer: DiscoveredPeer) {
        self.found.lock().unwrap().push(peer);
    }
}

#[clause("PNP-005-MUST-042", "PNP-005-MUST-043")]
#[tokio::test]
async fn nodes_find_each_other_over_mdns_and_attempt_connections() {
    let (_, id_a) = identity(71);
    let (_, id_b) = identity(72);
    let (_, id_c) = identity(73);

    // The mDNS port, unless something on this machine holds it exclusively.
    let mut port = MDNS_PORT;
    if MdnsDiscovery::new(id_c, 1).announce(&id_c).await.is_err() {
        port = 45353;
        if let Err(e) = MdnsDiscovery::new(id_c, 1)
            .with_mdns_port(port)
            .announce(&id_c)
            .await
        {
            // No multicast at all here (a sandbox without a network): nothing to test.
            eprintln!("skipping the mDNS socket test: {e}");
            return;
        }
    }

    let a = Arc::new(MdnsDiscovery::new(id_a, 7001).with_mdns_port(port));
    let b = Arc::new(MdnsDiscovery::new(id_b, 7002).with_mdns_port(port));
    let seen_by_a = Arc::new(Recorder {
        found: Mutex::new(Vec::new()),
    });
    let seen_by_b = Arc::new(Recorder {
        found: Mutex::new(Vec::new()),
    });
    let run_a = {
        let (a, r) = (a.clone(), seen_by_a.clone());
        tokio::spawn(async move { a.run(r).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let run_b = {
        let (b, r) = (b.clone(), seen_by_b.clone());
        tokio::spawn(async move { b.run(r).await })
    };

    // MUST-043: each hears the other's announcement and attempts a connection to it,
    // at the port the announcement gives.
    let (ra, rb) = (seen_by_a.clone(), seen_by_b.clone());
    eventually(
        Duration::from_secs(10),
        "the two nodes to discover each other",
        move || {
            ra.found.lock().unwrap().iter().any(|p| p.peer_id == id_b)
                && rb.found.lock().unwrap().iter().any(|p| p.peer_id == id_a)
        },
    )
    .await;
    let b_as_seen = seen_by_a
        .found
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.peer_id == id_b)
        .cloned()
        .unwrap();
    assert_eq!(b_as_seen.addr.port(), 7002);
    let a_as_seen = seen_by_b
        .found
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.peer_id == id_a)
        .cloned()
        .unwrap();
    assert_eq!(a_as_seen.addr.port(), 7001);
    // Neither connects to itself.
    assert!(
        seen_by_a
            .found
            .lock()
            .unwrap()
            .iter()
            .all(|p| p.peer_id != id_a)
    );
    assert!(
        seen_by_b
            .found
            .lock()
            .unwrap()
            .iter()
            .all(|p| p.peer_id != id_b)
    );

    // MUST-042: a node that asks the network gets both, each from its own announcement.
    let found = MdnsDiscovery::new(id_c, 7003)
        .with_mdns_port(port)
        .discover()
        .await
        .unwrap();
    let ids: HashSet<PeerId> = found.iter().map(|p| p.peer_id).collect();
    assert!(ids.contains(&id_a) && ids.contains(&id_b), "found {ids:?}");
    run_a.abort();
    run_b.abort();
}

#[clause("PNP-005-MUST-044")]
#[tokio::test(start_paused = true)]
async fn bootstrap_peers_get_no_special_trust() {
    let node = manager(1);
    let bootstrap = connect_as(&node, 2, PeerOrigin::Bootstrap).await.unwrap();
    let ordinary = connect_as(&node, 3, PeerOrigin::Manual).await.unwrap();
    assert_eq!(
        node.pool().origin(&bootstrap.id).await,
        Some(PeerOrigin::Bootstrap)
    );
    // A bootstrap peer goes through the sync phase like anyone.
    assert!(node.is_syncing(&bootstrap.id).await);
    finish_sync(&node, &bootstrap).await;
    finish_sync(&node, &ordinary).await;
    let score = |peer: PeerId| {
        let node = node.clone();
        async move { node.pool().get_score(&peer).await.map(|s| s.score) }
    };
    assert_eq!(score(bootstrap.id).await, score(ordinary.id).await);

    // What it sends is validated like anyone's: a forged signature, missing proof of
    // work, an expired message, each refused, each at the usual price.
    let mut forged = Draft::new(&identity(9).0).difficulty(0).build();
    forged.sig = vec![0; 64];
    let mut unproven = Draft::new(&identity(9).0).difficulty(0).build();
    while pow_zero_bits(&unproven) >= 16 {
        unproven = Draft::new(&identity(9).0).difficulty(0).build();
    }
    let expired = Draft::new(&identity(9).0)
        .ts(now_secs() - 500)
        .lifetime(100)
        .build();
    for bad in [&forged, &unproven, &expired] {
        assert!(deliver(&node, &bootstrap, bad).await.is_err());
        assert!(deliver(&node, &ordinary, bad).await.is_err());
        assert_eq!(score(bootstrap.id).await, score(ordinary.id).await);
    }
    assert_eq!(score(bootstrap.id).await, Some(78));

    // Its messages are rate limited by source like anyone's.
    let source = identity(10).0;
    for _ in 0..10 {
        deliver(&node, &bootstrap, &Draft::new(&source).build())
            .await
            .unwrap();
    }
    let outcome = node
        .gossip()
        .process_gossip(
            Some(bootstrap.id),
            &Draft::new(&source).build().to_cbor().unwrap(),
        )
        .await;
    assert_eq!(outcome.unwrap(), GossipAction::RateLimited);

    // And it is thrown out and refused like anyone when its score goes below zero.
    for _ in 0..9 {
        let _ = deliver(&node, &bootstrap, &forged).await;
    }
    assert!(!node.pool().is_connected(&bootstrap.id).await);
    assert!(matches!(
        connect_as(&node, 2, PeerOrigin::Bootstrap).await,
        Err(MeshError::PeerBanned)
    ));
    assert!(node.pool().is_connected(&ordinary.id).await);
}

#[clause("PNP-005-SHOULD-011")]
#[tokio::test(start_paused = true)]
async fn a_node_announces_its_addresses_every_30_minutes_and_when_they_change() {
    let node = manager(1);
    let peer = active_peer(&node, 2).await;
    let announcements = || -> Vec<PeerAnnouncement> {
        peer.gossip()
            .iter()
            .filter(|e| e.payload_type == ANNOUNCE)
            .map(|e| {
                assert_eq!(e.src, node.peer_id());
                PeerAnnouncement::from_cbor(&e.payload).unwrap()
            })
            .collect()
    };
    let first: SocketAddr = "192.0.2.10:4000".parse().unwrap();
    let second: SocketAddr = "192.0.2.99:4001".parse().unwrap();

    // Told its address, the node announces it.
    node.set_listen_addrs(vec![first]).await.unwrap();
    let seen = announcements();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].peer_id, node.peer_id());
    assert_eq!(seen[0].addrs, vec![first.to_string()]);

    // Then every 30 minutes.
    tokio::time::sleep(Duration::from_secs(29 * 60)).await;
    assert_eq!(announcements().len(), 1);
    tokio::time::sleep(Duration::from_secs(2 * 60)).await;
    assert_eq!(announcements().len(), 2);
    tokio::time::sleep(Duration::from_secs(60 * 60)).await;
    assert_eq!(announcements().len(), 4);
    // Telling it the same addresses again is not a change.
    node.set_listen_addrs(vec![first]).await.unwrap();
    assert_eq!(announcements().len(), 4);
    // A change is announced at once.
    node.set_listen_addrs(vec![first, second]).await.unwrap();
    let seen = announcements();
    assert_eq!(seen.len(), 5);
    assert_eq!(seen[4].addrs, vec![first.to_string(), second.to_string()]);

    // A node that receives an announcement learns the addresses, if the announcement
    // is the announcing node's own.
    let listener = manager(3);
    let relayer = active_peer(&listener, 4).await;
    let wire = peer
        .gossip()
        .iter()
        .rfind(|e| e.payload_type == ANNOUNCE)
        .unwrap()
        .clone();
    deliver(&listener, &relayer, &wire).await.unwrap();
    assert_eq!(listener.known_addrs(&node.peer_id()), vec![first, second]);
    let lie = PeerAnnouncement {
        peer_id: node.peer_id(),
        addrs: vec!["203.0.113.66:1".into()],
    };
    let forged = Draft::new(&identity(66).0)
        .payload_type(ANNOUNCE)
        .payload(lie.to_cbor().unwrap())
        .build();
    deliver(&listener, &relayer, &forged).await.unwrap();
    assert_eq!(listener.known_addrs(&node.peer_id()), vec![first, second]);
}

// ── §7 What is on disk; panic wipe ────────────────────────────

fn scratch_file(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pnp005-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("store.bin")
}

#[clause("PNP-005-MUST-048")]
#[tokio::test]
async fn buffers_are_encrypted_at_rest_under_a_key_derived_from_the_identity_key() {
    let now = now_secs();
    let (key, _) = identity(1);
    let recipient = PeerId([0xB0; 32]);
    let marker = b"PLAINTEXT-MARKER-0123456789";
    let store = InMemoryStore::with_identity(&key);
    for n in 0..3u32 {
        let mut m = bare(n, now + 5000, 7, now, 0);
        m.payload = [marker.as_slice(), &n.to_be_bytes()].concat();
        store.store(&recipient, &m).await.unwrap();
    }
    let path = scratch_file("at-rest");
    store.persist(&path).await.unwrap();

    // Nothing of the buffer is readable in the file: not the payload, not who it is
    // for, not who it is from.
    let file = std::fs::read(&path).unwrap();
    assert!(file.len() > 300);
    assert!(!file.windows(marker.len()).any(|w| w == marker));
    assert!(!file.windows(32).any(|w| w == recipient.0));
    assert!(!file.windows(16).any(|w| w == [7u8; 16]));
    assert!(
        !file.windows(16).any(|w| w == [0u8; 16]),
        "structure shows through"
    );

    // The key comes from the identity key: another store made from the same identity
    // reads it...
    let same = InMemoryStore::with_identity(&key);
    assert_eq!(same.load(&path).await.unwrap(), 3);
    let read: Vec<Vec<u8>> = same
        .retrieve(&recipient)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.payload)
        .collect();
    assert_eq!(read.len(), 3);
    assert!(read.iter().all(|p| p.starts_with(marker)));
    // ...one made from any other key, or from none, does not.
    assert!(
        InMemoryStore::with_identity(&identity(2).0)
            .load(&path)
            .await
            .is_err()
    );
    assert!(InMemoryStore::new().load(&path).await.is_err());
    // Two snapshots of the same buffer are not the same bytes.
    let again = scratch_file("at-rest-2");
    store.persist(&again).await.unwrap();
    assert_ne!(std::fs::read(&again).unwrap(), file);
    // A changed file is refused, not half read.
    let mut damaged = file.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    std::fs::write(&again, damaged).unwrap();
    assert!(
        InMemoryStore::with_identity(&key)
            .load(&again)
            .await
            .is_err()
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&again);
}

#[clause("PNP-005-SHOULD-016")]
#[tokio::test(start_paused = true)]
async fn panic_wipe_erases_everything_buffered() {
    let node = manager(1);
    let feeder = active_peer(&node, 2).await;
    let bob = active_peer(&node, 3).await;
    node.remove_peer(&bob.id).await;
    let for_bob = Draft::new(&identity(9).0)
        .payload(user_payload(bob.id, b"buffered"))
        .build();
    deliver(&node, &feeder, &for_bob).await.unwrap();
    let path = scratch_file("wipe");
    node.store().persist(&path).await.unwrap();
    assert_eq!(node.store().total_count().await, 1);
    assert_eq!(node.gossip().cached_ids().len(), 1);
    assert!(path.exists());

    node.panic_wipe().await.unwrap();

    // The buffers are empty, the file is gone, and so is what the node held for sync
    // and what it remembered having seen.
    assert_eq!(node.store().total_count().await, 0);
    assert!(!path.exists(), "the persisted buffer survived the wipe");
    assert!(node.gossip().cached_ids().is_empty());
    assert!(!node.gossip().dedup.is_seen(&for_bob.message_id().unwrap()));
    // Bob coming back gets nothing.
    let bob = connect(&node, 3).await;
    finish_sync(&node, &bob).await;
    assert!(bob.gossip().is_empty());
}

// ── §7 item 2: into the mesh through a circuit ────────────────

#[clause("PNP-005-SHOULD-015")]
#[tokio::test(start_paused = true)]
async fn a_message_can_enter_the_mesh_at_the_far_end_of_a_relay_circuit() {
    // Three relays; the third is also a mesh node, with one mesh peer.
    let exit_mesh = manager(60);
    let mesh_peer = active_peer(&exit_mesh, 61).await;
    let net = RelayNet::new();
    let relays = net.start_with(3, &|index| {
        (index == 3).then(|| Arc::new(GossipExit::new(exit_mesh.clone())) as Arc<dyn ExitHandler>)
    });
    let path: Vec<_> = relays.iter().map(|r| r.info.clone()).collect();
    let circuit = StandardCircuitBuilder::with_dialer(net.op_dialer())
        .build_established(&path)
        .await
        .unwrap();

    // The originator has a gossip engine and no mesh connection at all.
    let (key, id) = identity(62);
    let pool = Arc::new(ConnectionPool::new());
    let gossip = StandardGossip::new(id, key, pool.clone());
    let recipient = identity(63).1;
    let message = gossip
        .build_envelope(
            USER,
            user_payload(recipient, b"via the circuit"),
            GossipParams::default(),
            Origin::Anonymous,
        )
        .unwrap();

    let accepted = inject_via_circuit(&circuit, &message.to_cbor().unwrap())
        .await
        .unwrap();
    assert!(accepted, "the exit refused a valid gossip message");
    after_jitter().await;

    // The message is in the mesh: the exit's peer has it, one hop from the exit.
    let arrived = mesh_peer.gossip();
    assert_eq!(arrived.len(), 1);
    assert_eq!(arrived[0].id, message.id);
    assert_eq!((arrived[0].hops, arrived[0].ttl), (1, message.ttl - 1));
    // The mesh never had a connection from the originator, and the guard relay, which
    // did, saw only cells.
    assert_eq!(pool.peer_count().await, 0);
    assert_eq!(exit_mesh.peer_count().await, 1);
    assert!(relays[0].delivered.lock().unwrap().is_empty());
    for tap in net.taps() {
        for cell in tap.from_end.sent() {
            assert!(!cell.windows(15).any(|w| w == b"via the circuit"));
        }
    }

    // The exit validates what it injects: something that is not a valid gossip
    // message is not put into the mesh, and the originator is told.
    let mut invalid = gossip
        .build_envelope(
            GROUP,
            b"x".to_vec(),
            GossipParams::default(),
            Origin::Identity,
        )
        .unwrap();
    invalid.sig = vec![0; 64];
    let accepted = inject_via_circuit(&circuit, &invalid.to_cbor().unwrap())
        .await
        .unwrap();
    assert!(!accepted);
    after_jitter().await;
    assert_eq!(mesh_peer.gossip().len(), 1);

    // A circuit is a source like any other: ten messages a minute, the rest refused.
    let mut taken = 0;
    for _ in 0..12 {
        let more = gossip
            .build_envelope(
                USER,
                user_payload(recipient, b"more"),
                GossipParams::default(),
                Origin::Anonymous,
            )
            .unwrap();
        if inject_via_circuit(&circuit, &more.to_cbor().unwrap())
            .await
            .unwrap()
        {
            taken += 1;
        }
    }
    // Two were counted above.
    assert_eq!(taken, 8);
}
