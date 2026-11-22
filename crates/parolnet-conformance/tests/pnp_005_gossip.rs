//! PNP-005 conformance: the gossip envelope, validation (§5.1) and forwarding (§5.2).
//!
//! Every test feeds envelopes to a gossip node (`StandardGossip`) the way a peer would
//! and looks at what the node does: what it returns, what it sends to which of its
//! peers and when, and how it scores the peer the message came from. The peers are
//! in-memory connections that record what is sent on them.
//!
//! A relay in the default signaling-only profile takes no part in any of this
//! (PNP-005-MUST-049, tested in `pnp_001_signaling_only.rs`); the gossip engine is
//! library code for clients' own connections and for the opt-in relay profile.

mod inproc;

use ed25519_dalek::SigningKey;
use inproc::{
    Draft, PipeEnd, gossip_frames, identity, now_secs, pipe, pow_zero_bits, reprove, resign,
};
use parolnet_clause::clause;
use parolnet_mesh::clock::Clock;
use parolnet_mesh::connection_pool::ConnectionPool;
use parolnet_mesh::gossip::{
    DedupFilter, GossipParams, Origin, SeenBloomFilter, StandardGossip, verify_anonymous_origin,
};
use parolnet_mesh::{GossipAction, MeshError};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::{GossipEnvelope, GossipPayloadType, RelayDescriptorGossip};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

const USER: u8 = GossipPayloadType::UserMessage as u8;
const GROUP: u8 = GossipPayloadType::GroupMetadata as u8;
const DESCRIPTOR: u8 = GossipPayloadType::RelayDescriptor as u8;

/// A change to one field of an envelope.
type Change = Box<dyn Fn(&mut GossipEnvelope)>;

struct Node {
    gossip: StandardGossip,
    pool: Arc<ConnectionPool>,
    id: PeerId,
}

fn node(seed: u8) -> Node {
    node_with_clock(seed, Clock::system())
}

fn node_with_clock(seed: u8, clock: Clock) -> Node {
    let (key, id) = identity(seed);
    let pool = Arc::new(ConnectionPool::new());
    Node {
        gossip: StandardGossip::with_clock(id, key, pool.clone(), clock),
        pool,
        id,
    }
}

impl Node {
    /// Connect a peer; the returned end records what the node sends to it.
    async fn peer(&self, seed: u8) -> (PeerId, Arc<PipeEnd>) {
        let (_, id) = identity(seed);
        let (near, far) = pipe();
        // The far end is kept alive by leaking it: the peer never hangs up.
        std::mem::forget(far);
        self.pool.add_peer(id, near.clone()).await.unwrap();
        (id, near)
    }

    async fn score(&self, peer: &PeerId) -> i32 {
        self.pool.get_score(peer).await.unwrap().score
    }

    async fn receive(
        &self,
        from: Option<PeerId>,
        envelope: &GossipEnvelope,
    ) -> Result<GossipAction, MeshError> {
        self.gossip
            .process_gossip(from, &envelope.to_cbor().unwrap())
            .await
    }
}

/// Longer than any forwarding jitter.
async fn after_jitter() {
    tokio::time::sleep(Duration::from_millis(250)).await;
}

fn key(seed: u8) -> SigningKey {
    identity(seed).0
}

// ── §3.1 Envelope ─────────────────────────────────────────────

#[clause("PNP-005-MUST-001", "PNP-005-MUST-012")]
#[tokio::test(start_paused = true)]
async fn the_version_is_1_and_any_other_is_silently_discarded() {
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    let (_, other_end) = n.peer(3).await;

    // What the node originates says v = 1.
    let own = n
        .gossip
        .build_envelope(
            GROUP,
            b"x".to_vec(),
            GossipParams::default(),
            Origin::Identity,
        )
        .unwrap();
    assert_eq!(own.v, 1);

    // A properly made envelope of another version: discarded, and silently. Nothing is
    // forwarded, nothing is sent back, and the sender is not penalized for speaking a
    // version this node does not know.
    for version in [0u8, 2, 255] {
        let mut envelope = Draft::new(&key(9)).build();
        envelope.v = version;
        resign(&mut envelope, &key(9));
        let outcome = n.receive(Some(sender), &envelope).await;
        assert!(
            matches!(outcome, Err(MeshError::UnsupportedVersion)),
            "v={version}"
        );
        assert!(GossipEnvelope::from_cbor(&envelope.to_cbor().unwrap()).is_err());
    }
    after_jitter().await;
    assert!(gossip_frames(&other_end).is_empty());
    assert!(sender_end.sent().is_empty());
    assert_eq!(n.score(&sender).await, 100);

    // The same envelope with v = 1 goes through.
    let envelope = Draft::new(&key(9)).build();
    assert!(n.receive(Some(sender), &envelope).await.is_ok());
    after_jitter().await;
    assert_eq!(gossip_frames(&other_end).len(), 1);
}

#[clause("PNP-005-MUST-002")]
#[tokio::test(start_paused = true)]
async fn a_forwarding_node_puts_itself_in_the_seen_filter() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;
    let envelope = Draft::new(&key(9)).build();
    let originator = identity(9).1;
    let before = SeenBloomFilter::from_bytes(&envelope.seen).unwrap();
    assert!(before.probably_contains(&originator));
    assert!(!before.probably_contains(&n.id));

    n.receive(Some(sender), &envelope).await.unwrap();
    after_jitter().await;
    let forwarded = &gossip_frames(&out)[0];
    let after = SeenBloomFilter::from_bytes(&forwarded.seen).unwrap();
    assert!(
        after.probably_contains(&n.id),
        "the forwarder is not in `seen`"
    );
    assert!(after.probably_contains(&originator), "`seen` lost an entry");

    // The filter is the one the spec defines: bit h_k = SHA-256(k || PeerId) mod 1024
    // for k in 0, 1, 2, and only those bits are new.
    let mut expected = before.as_bytes().to_vec();
    for k in 0u8..3 {
        let mut h = Sha256::new();
        h.update([k]);
        h.update(n.id.0);
        let digest = h.finalize();
        let bit = u16::from_be_bytes([digest[0], digest[1]]) as usize % 1024;
        expected[bit / 8] |= 1 << (bit % 8);
    }
    assert_eq!(forwarded.seen, expected);
}

#[clause("PNP-005-MUST-003")]
#[tokio::test(start_paused = true)]
async fn the_signature_survives_forwarding_and_nothing_else() {
    // A originates, B forwards, C receives: `seen`, `hops` (and the `ttl` that moves
    // with it) changed on the way, and the originator's signature still verifies.
    let a = node(1);
    let b = node(2);
    let (_, b_out) = b.peer(30).await;
    let original = a
        .gossip
        .build_envelope(
            GROUP,
            b"signed once".to_vec(),
            GossipParams::default(),
            Origin::Identity,
        )
        .unwrap();
    b.receive(Some(a.id), &original).await.unwrap();
    after_jitter().await;
    let forwarded = gossip_frames(&b_out)[0].clone();
    assert_ne!(forwarded.seen, original.seen);
    assert_eq!((forwarded.hops, forwarded.ttl), (1, original.ttl - 1));
    assert_eq!(forwarded.sig, original.sig, "a forwarder re-signed");
    assert_eq!(
        node(3).receive(Some(b.id), &forwarded).await.unwrap(),
        GossipAction::Deliver
    );
    // A second and a third hop too.
    let c = node(4);
    let (_, c_out) = c.peer(31).await;
    c.receive(Some(b.id), &forwarded).await.unwrap();
    after_jitter().await;
    let twice = gossip_frames(&c_out)[0].clone();
    assert_eq!((twice.hops, twice.ttl), (2, original.ttl - 2));
    assert!(node(5).receive(Some(c.id), &twice).await.is_ok());

    // `seen` is not signed: any value verifies.
    let mut other_seen = forwarded.clone();
    other_seen.seen = vec![0xFF; 128];
    assert!(node(6).receive(None, &other_seen).await.is_ok());

    // Every other field is: change one in transit and the signature fails.
    let changes: Vec<(&str, Change)> = vec![
        ("id", Box::new(|e| e.id[0] ^= 1)),
        ("ts", Box::new(|e| e.ts += 1)),
        ("exp", Box::new(|e| e.exp -= 1)),
        ("ttl", Box::new(|e| e.ttl += 1)),
        ("pow", Box::new(|e| e.pow[0] ^= 1)),
        ("type", Box::new(|e| e.payload_type = 0x05)),
        ("payload", Box::new(|e| e.payload[0] ^= 1)),
        (
            "src",
            Box::new(|e| {
                let (_, other) = identity(77);
                e.src = other;
                e.src_pubkey = key(77).verifying_key().to_bytes().to_vec();
            }),
        ),
    ];
    for (field, change) in changes {
        let mut tampered = forwarded.clone();
        change(&mut tampered);
        let outcome = node(7).receive(None, &tampered).await;
        assert!(
            matches!(outcome, Err(MeshError::InvalidSignature)),
            "a changed {field} was not caught by the signature: {outcome:?}"
        );
    }
}

#[clause("PNP-005-MUST-004")]
#[tokio::test(start_paused = true)]
async fn the_sender_finds_a_nonce_that_meets_the_difficulty() {
    let n = node(1);
    for _ in 0..3 {
        let envelope = n
            .gossip
            .build_envelope(
                GROUP,
                b"work".to_vec(),
                GossipParams::default(),
                Origin::Identity,
            )
            .unwrap();
        assert_eq!(envelope.pow.len(), 8);
        // SHA-256(SHA-256("pgmp-pow-v1" || id || src || ts) || nonce), computed here.
        assert!(
            pow_zero_bits(&envelope) >= 16,
            "{} zero bits",
            pow_zero_bits(&envelope)
        );
        // The nonce is the thing: another one does not do.
        let mut other = envelope.clone();
        other.pow[7] ^= 0x5A;
        other.pow[3] ^= 0xA5;
        assert!(pow_zero_bits(&other) < 16 || other.pow == envelope.pow);
    }
    // A relay descriptor is made with 20.
    let payload = RelayDescriptorGossip {
        descriptor: vec![1, 2, 3],
        pow_difficulty: None,
    }
    .to_cbor()
    .unwrap();
    let descriptor = n
        .gossip
        .build_envelope(
            DESCRIPTOR,
            payload,
            GossipParams::for_type(DESCRIPTOR),
            Origin::Identity,
        )
        .unwrap();
    assert!(pow_zero_bits(&descriptor) >= 20);
}

// ── §3.5 Anonymous envelopes ──────────────────────────────────

#[clause(
    "PNP-005-MUST-005",
    "PNP-005-MUST-006",
    "PNP-005-SHOULD-001",
    "PNP-005-SHOULD-013"
)]
#[tokio::test(start_paused = true)]
async fn user_messages_go_out_with_no_sender_in_the_envelope() {
    let n = node(1);
    let (_, out) = n.peer(2).await;
    let public = key(1).verifying_key().to_bytes();

    // A node's user messages are anonymous unless it is told otherwise.
    assert_eq!(n.gossip.user_origin, Origin::Anonymous);
    n.gossip
        .publish(USER, b"sealed elsewhere".to_vec())
        .await
        .unwrap();
    let sent = gossip_frames(&out).pop().expect("the message went out");
    // MUST-005: src is 32 zero bytes. MUST-006: src_pubkey is the empty byte string.
    assert_eq!(sent.src, PeerId([0u8; 32]));
    assert!(sent.src_pubkey.is_empty());
    assert!(sent.is_anonymous());
    // Neither the PeerId nor the key is anywhere in what went on the wire.
    let wire = out.sent().pop().unwrap();
    assert!(!wire.windows(32).any(|w| w == n.id.0));
    assert!(!wire.windows(32).any(|w| w == public));
    // The signature is there and is the sender's, over the zeroed fields.
    assert!(verify_anonymous_origin(&sent, &public).is_ok());

    // The decoder's rule: a zero src goes with an empty key, both or neither.
    let mut half = sent.clone();
    half.src = n.id;
    assert!(!half.is_valid_structure());
    let mut made = Draft::new(&key(1)).build();
    made.make_anonymous();
    assert_eq!(made.src, PeerId([0u8; 32]));
    assert!(made.src_pubkey.is_empty());
}

#[clause("PNP-005-MUST-009", "PNP-005-MUST-010")]
#[tokio::test(start_paused = true)]
async fn only_user_messages_may_be_anonymous() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;

    for payload_type in [0x01u8, 0x03, 0x04, 0x05] {
        // An originator does not build one.
        assert!(
            n.gossip
                .build_envelope(
                    payload_type,
                    vec![1],
                    GossipParams::default(),
                    Origin::Anonymous
                )
                .is_err()
        );
        // One that arrives anyway (well-formed, proof of work for its type and all) is
        // refused: there is no `src` to verify it against.
        let bits = if payload_type == 0x01 { 20 } else { 16 };
        let anonymous = Draft::new(&key(9))
            .payload_type(payload_type)
            .difficulty(bits)
            .anonymous()
            .build();
        let before = n.score(&sender).await;
        let outcome = n.receive(Some(sender), &anonymous).await;
        assert!(
            outcome.is_err(),
            "anonymous type {payload_type:#04x} accepted"
        );
        assert_eq!(n.score(&sender).await, before - 10);

        // With a real src and key the same type is accepted.
        let named = Draft::new(&key(9))
            .payload_type(payload_type)
            .difficulty(bits)
            .build();
        assert_ne!(named.src, PeerId([0u8; 32]));
        assert_eq!(named.src_pubkey.len(), 32);
        assert!(n.receive(Some(sender), &named).await.is_ok());
    }
    after_jitter().await;
    let forwarded = gossip_frames(&out);
    assert_eq!(forwarded.len(), 4);
    assert!(forwarded.iter().all(|e| !e.is_anonymous()));

    // A zero src with a key attached is not a valid non-anonymous envelope either.
    let mut zero_src = Draft::new(&key(9)).payload_type(0x04).build();
    zero_src.src = PeerId([0u8; 32]);
    reprove(&mut zero_src, 16);
    resign(&mut zero_src, &key(9));
    assert!(n.receive(Some(sender), &zero_src).await.is_err());
}

#[clause("PNP-005-SHOULD-002")]
#[tokio::test(start_paused = true)]
async fn an_anonymous_user_message_is_relayed_without_a_signature_check() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;
    // The relay has no key to check the signature with, and does not need one: an
    // envelope whose signature is not the originator's at all still passes.
    let mut envelope = Draft::new(&key(9)).anonymous().build();
    envelope.sig = vec![0xAB; 64];
    let outcome = n.receive(Some(sender), &envelope).await.unwrap();
    assert!(matches!(outcome, GossipAction::Forward { .. }));
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 1);
    assert_eq!(n.score(&sender).await, 101);
    // The check is the recipient's, with the key from the decrypted payload
    // (`pnp_005_mesh.rs`): against the real originator's key this one fails.
    assert!(verify_anonymous_origin(&envelope, &key(9).verifying_key().to_bytes()).is_err());
}

#[clause("PNP-005-SHOULD-014")]
#[tokio::test(start_paused = true)]
async fn the_fallback_source_is_a_pseudonym_not_the_node_identity() {
    let (signing, id) = identity(1);
    let pool = Arc::new(ConnectionPool::new());
    let mut gossip = StandardGossip::new(id, signing.clone(), pool.clone());
    gossip.user_origin = Origin::Pseudonym;
    let (near, far) = pipe();
    pool.add_peer(identity(2).1, near.clone()).await.unwrap();

    gossip.publish(USER, b"first".to_vec()).await.unwrap();
    gossip.publish(USER, b"second".to_vec()).await.unwrap();
    let sent = gossip_frames(&near);
    assert_eq!(sent.len(), 2);
    let pseudonym = sent[0].src;
    // Not the node's identity, nor its key.
    assert_ne!(pseudonym, id);
    assert_ne!(pseudonym, PeerId([0u8; 32]));
    assert_ne!(sent[0].src_pubkey, signing.verifying_key().to_bytes());
    // A PeerId in its own right: the hash of the key it signs with, the same one each
    // time, made from the identity key for this purpose.
    assert_eq!(
        pseudonym.0,
        <[u8; 32]>::from(Sha256::digest(&sent[0].src_pubkey))
    );
    assert_eq!(sent[1].src, pseudonym);
    assert_eq!(pseudonym, gossip.pseudonym_peer_id());
    // Other nodes verify it like any source.
    for envelope in &sent {
        assert!(node(5).receive(None, envelope).await.is_ok());
    }
    // Everything that is not a user message still carries the identity.
    gossip.publish(GROUP, b"group".to_vec()).await.unwrap();
    assert_eq!(gossip_frames(&near)[2].src, id);
    drop(far);
}

// ── §5.1 Validation ───────────────────────────────────────────

#[clause("PNP-005-MUST-011")]
#[tokio::test(start_paused = true)]
async fn the_checks_run_in_the_order_the_spec_gives() {
    let now = now_secs();
    let k = key(9);
    // An envelope wrong in several ways at once is refused for the first of them:
    // version, expiry, TTL, signature, proof of work, deduplication, payload size.
    let verdict = |envelope: GossipEnvelope| async move { node(1).receive(None, &envelope).await };

    // 1 before 2: wrong version and expired.
    let mut e = Draft::new(&k).ts(now - 1000).lifetime(10).build();
    e.v = 3;
    assert!(matches!(
        verdict(e).await,
        Err(MeshError::UnsupportedVersion)
    ));

    // 2 before 3, 4, 5: expired, an impossible TTL, a bad signature, no proof of work.
    let mut e = Draft::new(&k).ts(now - 1000).lifetime(10).build();
    e.ttl = 40;
    e.sig = vec![0; 64];
    e.pow = vec![0xFF; 8];
    assert!(matches!(verdict(e).await, Err(MeshError::MessageExpired)));

    // 3 before 4: an impossible TTL and a bad signature.
    let mut e = Draft::new(&k).build();
    e.ttl = 40;
    e.sig = vec![0; 64];
    match verdict(e).await {
        Err(MeshError::ValidationFailed(why)) => assert!(why.contains("ttl"), "{why}"),
        other => panic!("{other:?}"),
    }

    // 4 before 5: a bad signature and no proof of work.
    let mut e = Draft::new(&k).build();
    e.pow = vec![0xFF; 8];
    e.sig = vec![0; 64];
    assert!(matches!(verdict(e).await, Err(MeshError::InvalidSignature)));

    // 5 before 6 and 7: no proof of work, already seen, payload too large.
    let n = node(2);
    let mut big = Draft::new(&k).payload(vec![7u8; 65537]).build();
    n.gossip.dedup.mark_seen(big.message_id().unwrap());
    let good_pow = big.pow.clone();
    big.pow = vec![0xFF; 8];
    resign(&mut big, &k);
    assert!(matches!(
        n.receive(None, &big).await,
        Err(MeshError::InsufficientPoW)
    ));

    // 6 before 7: already seen and payload too large.
    big.pow = good_pow;
    resign(&mut big, &k);
    assert_eq!(n.receive(None, &big).await.unwrap(), GossipAction::Drop);

    // 7: only the payload is wrong.
    assert!(matches!(
        node(3).receive(None, &big).await,
        Err(MeshError::PayloadTooLarge)
    ));
}

#[clause("PNP-005-MUST-013")]
#[tokio::test(start_paused = true)]
async fn an_expired_message_is_discarded() {
    // The node's clock is held by the test.
    let now = Arc::new(AtomicU64::new(1_800_000_000));
    let clock = {
        let now = now.clone();
        Clock::from_fn(move || now.load(Ordering::SeqCst))
    };
    let n = node_with_clock(1, clock);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;
    let t0 = now.load(Ordering::SeqCst);

    let message = |lifetime: u64| Draft::new(&key(9)).ts(t0).lifetime(lifetime).build();
    // One second before its expiry a message is taken.
    let alive = message(100);
    now.store(t0 + 99, Ordering::SeqCst);
    assert!(n.receive(Some(sender), &alive).await.is_ok());
    // At the expiry (current time >= exp) and after, not.
    for late in [100u64, 101, 5000] {
        let dead = message(100);
        now.store(t0 + late, Ordering::SeqCst);
        let outcome = n.receive(Some(sender), &dead).await;
        assert!(
            matches!(outcome, Err(MeshError::MessageExpired)),
            "+{late}s: {outcome:?}"
        );
    }
    after_jitter().await;
    assert_eq!(
        gossip_frames(&out).len(),
        1,
        "an expired message was forwarded"
    );
}

#[clause("PNP-005-MUST-014")]
#[tokio::test(start_paused = true)]
async fn a_message_with_ttl_0_is_not_forwarded() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;

    // Signed by its originator with TTL 1, one hop ago: valid, and at its last stop.
    let mut last_hop = Draft::new(&key(9)).payload_type(GROUP).ttl(1).build();
    last_hop.ttl = 0;
    last_hop.hops = 1;
    let outcome = n.receive(Some(sender), &last_hop).await.unwrap();
    // It may be delivered here (a broadcast type is)...
    assert_eq!(outcome, GossipAction::Deliver);
    // ...and goes no further.
    after_jitter().await;
    assert!(
        gossip_frames(&out).is_empty(),
        "a TTL-0 message was forwarded"
    );
    assert_eq!(
        n.score(&sender).await,
        101,
        "TTL 0 is valid, not an offence"
    );

    // With one hop left it is forwarded, with TTL 0.
    let one_left = Draft::new(&key(9)).payload_type(GROUP).ttl(1).build();
    n.receive(Some(sender), &one_left).await.unwrap();
    after_jitter().await;
    let forwarded = gossip_frames(&out);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].ttl, 0);
}

#[clause("PNP-005-MUST-015", "PNP-005-MUST-016")]
#[tokio::test(start_paused = true)]
async fn a_bad_signature_discards_the_message_and_penalizes_the_sending_peer() {
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    // The peer the forged message names as its source is connected too.
    let (victim, _) = n.peer(9).await;
    let (_, out) = n.peer(3).await;

    // Signed by someone else's key, claiming the victim as src.
    let mut forged = Draft::new(&key(9)).build();
    forged.sig = {
        let mut copy = forged.clone();
        resign(&mut copy, &key(66));
        copy.sig
    };
    let outcome = n.receive(Some(sender), &forged).await;
    assert!(matches!(outcome, Err(MeshError::InvalidSignature)));
    // A key that is not the one `src` is the hash of.
    let mut wrong_key = Draft::new(&key(9)).build();
    wrong_key.src_pubkey = key(66).verifying_key().to_bytes().to_vec();
    resign(&mut wrong_key, &key(66));
    assert!(matches!(
        n.receive(Some(sender), &wrong_key).await,
        Err(MeshError::InvalidSignature)
    ));
    // A signature of the wrong length.
    let mut short = Draft::new(&key(9)).build();
    short.sig.truncate(63);
    assert!(n.receive(Some(sender), &short).await.is_err());

    after_jitter().await;
    // MUST-015/016: discarded, all three.
    assert!(gossip_frames(&out).is_empty());
    assert!(sender_end.sent().is_empty());
    // MUST-016: the peer that sent them pays, 10 points each. The peer whose name was
    // on them does not.
    assert_eq!(n.score(&sender).await, 70);
    assert_eq!(n.score(&victim).await, 100);

    // A correctly signed message from the same sender is fine.
    assert!(
        n.receive(Some(sender), &Draft::new(&key(9)).build())
            .await
            .is_ok()
    );
}

/// An envelope whose proof of work has fewer than `below` leading zero bits.
fn underpowered(k: &SigningKey, payload_type: u8, computed_at: u8, below: u32) -> GossipEnvelope {
    loop {
        let envelope = Draft::new(k)
            .payload_type(payload_type)
            .difficulty(computed_at)
            .build();
        if pow_zero_bits(&envelope) < below {
            return envelope;
        }
    }
}

#[clause("PNP-005-MUST-017", "PNP-005-MUST-035", "PNP-005-MUST-037")]
#[tokio::test(start_paused = true)]
async fn a_message_without_enough_proof_of_work_is_silently_discarded() {
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    let (_, out) = n.peer(3).await;

    // No proof of work at all, for each payload type and for a reserved one.
    for payload_type in [0x02u8, 0x03, 0x04, 0x05, 0x7F] {
        let none = underpowered(&key(9), payload_type, 0, 16);
        let outcome = n.receive(Some(sender), &none).await;
        assert!(
            matches!(outcome, Err(MeshError::InsufficientPoW)),
            "{payload_type:#04x}"
        );
    }
    // Close is not enough: 15 bits where 16 are asked.
    let nearly = loop {
        let e = underpowered(&key(9), GROUP, 12, 16);
        if pow_zero_bits(&e) >= 12 {
            break e;
        }
    };
    assert!(matches!(
        n.receive(Some(sender), &nearly).await,
        Err(MeshError::InsufficientPoW)
    ));
    // The node's own setting cannot lower the floor.
    let (k2, id2) = identity(4);
    let mut lax = StandardGossip::new(id2, k2, Arc::new(ConnectionPool::new()));
    lax.default_difficulty = 4;
    assert_eq!(lax.required_difficulty(GROUP), 16);
    assert!(matches!(
        lax.process_gossip(None, &nearly.to_cbor().unwrap()).await,
        Err(MeshError::InsufficientPoW)
    ));

    after_jitter().await;
    // Discarded: not forwarded. Silently: nothing went back to the sender.
    assert!(gossip_frames(&out).is_empty());
    assert!(sender_end.sent().is_empty());

    // Sixteen bits pass.
    let enough = Draft::new(&key(9))
        .payload_type(GROUP)
        .difficulty(16)
        .build();
    assert!(n.receive(Some(sender), &enough).await.is_ok());
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 1);
}

#[clause("PNP-005-MUST-036")]
#[tokio::test(start_paused = true)]
async fn a_relay_descriptor_needs_20_bits() {
    let n = node(1);
    let (_, out) = n.peer(3).await;
    assert_eq!(n.gossip.required_difficulty(DESCRIPTOR), 20);
    assert_eq!(n.gossip.required_difficulty(USER), 16);
    let payload = RelayDescriptorGossip {
        descriptor: vec![0xDE, 0x5C],
        pow_difficulty: None,
    }
    .to_cbor()
    .unwrap();

    // Sixteen bits, enough for any other type, are not enough here.
    let mut cheap = underpowered(&key(9), DESCRIPTOR, 16, 20);
    cheap.payload = payload.clone();
    reprove(&mut cheap, 16);
    while pow_zero_bits(&cheap) >= 20 {
        cheap.ts -= 1;
        reprove(&mut cheap, 16);
    }
    resign(&mut cheap, &key(9));
    assert!(pow_zero_bits(&cheap) >= 16);
    assert!(matches!(
        n.receive(None, &cheap).await,
        Err(MeshError::InsufficientPoW)
    ));

    // Twenty are.
    let proper = Draft::new(&key(9))
        .payload_type(DESCRIPTOR)
        .payload(payload)
        .difficulty(20)
        .build();
    assert!(n.receive(None, &proper).await.is_ok());
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 1);
}

#[clause("PNP-005-MUST-018", "PNP-005-MUST-033")]
#[tokio::test(start_paused = true)]
async fn a_message_seen_before_is_discarded() {
    let n = node(1);
    let (first_sender, _) = n.peer(2).await;
    let (second_sender, _) = n.peer(4).await;
    let (_, out) = n.peer(3).await;
    let envelope = Draft::new(&key(9)).build();
    let id = envelope.message_id().unwrap();

    assert!(!n.gossip.dedup.is_seen(&id));
    assert!(matches!(
        n.receive(Some(first_sender), &envelope).await.unwrap(),
        GossipAction::Forward { .. }
    ));
    // MUST-033: the node keeps the ID.
    assert!(n.gossip.dedup.is_seen(&id));

    // MUST-018: the same message again, from the same peer or another, with whatever
    // `seen` and hop count it picked up on the way: dropped.
    assert_eq!(
        n.receive(Some(first_sender), &envelope).await.unwrap(),
        GossipAction::Drop
    );
    let mut via_elsewhere = envelope.clone();
    via_elsewhere.ttl -= 2;
    via_elsewhere.hops += 2;
    via_elsewhere.seen = vec![0x0F; 128];
    assert_eq!(
        n.receive(Some(second_sender), &via_elsewhere)
            .await
            .unwrap(),
        GossipAction::Drop
    );
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 1, "a duplicate was forwarded");
    // A duplicate costs its sender a point.
    assert_eq!(n.score(&second_sender).await, 99);

    // The filter itself: what was marked is seen, what was not is not.
    let filter = DedupFilter::new();
    for i in 0..1000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        filter.mark_seen(id);
    }
    for i in 0..2000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        assert_eq!(filter.is_seen(&id), i < 1000, "id {i}");
    }
}

#[clause("PNP-005-MUST-019")]
#[tokio::test(start_paused = true)]
async fn a_payload_over_65536_bytes_is_discarded() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;

    let at_limit = Draft::new(&key(9)).payload(vec![1u8; 65536]).build();
    assert!(n.receive(Some(sender), &at_limit).await.is_ok());
    let over = Draft::new(&key(9)).payload(vec![1u8; 65537]).build();
    assert!(matches!(
        n.receive(Some(sender), &over).await,
        Err(MeshError::PayloadTooLarge)
    ));
    assert!(GossipEnvelope::from_cbor(&over.to_cbor().unwrap()).is_err());
    after_jitter().await;
    let forwarded = gossip_frames(&out);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].payload.len(), 65536);
    // Nor does a node originate one.
    assert!(matches!(
        n.gossip.build_envelope(
            GROUP,
            vec![0u8; 65537],
            GossipParams::default(),
            Origin::Identity
        ),
        Err(MeshError::PayloadTooLarge)
    ));
}

#[clause("PNP-005-MUST-045")]
#[tokio::test(start_paused = true)]
async fn a_timestamp_more_than_300_seconds_ahead_is_rejected() {
    let now = 1_800_000_000u64;
    let n = node_with_clock(1, Clock::from_fn(move || now));
    let (sender, _) = n.peer(2).await;
    let (_, out) = n.peer(3).await;

    // Within the tolerance for clock skew.
    for ahead in [0u64, 299, 300] {
        let e = Draft::new(&key(9)).ts(now + ahead).build();
        assert!(
            n.receive(Some(sender), &e).await.is_ok(),
            "+{ahead}s refused"
        );
    }
    // Beyond it.
    for ahead in [301u64, 3600, 86400 * 365] {
        let e = Draft::new(&key(9)).ts(now + ahead).build();
        let outcome = n.receive(Some(sender), &e).await;
        assert!(
            matches!(outcome, Err(MeshError::FutureTimestamp)),
            "+{ahead}s: {outcome:?}"
        );
    }
    // Or past the expiry.
    let e = Draft::new(&key(9)).ts(now - 200).lifetime(100).build();
    assert!(matches!(
        n.receive(Some(sender), &e).await,
        Err(MeshError::MessageExpired)
    ));
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 3);
}

// ── §5.2 Forwarding ───────────────────────────────────────────

#[clause(
    "PNP-005-MUST-020",
    "PNP-005-MUST-022",
    "PNP-005-MUST-027",
    "PNP-005-MUST-028"
)]
#[tokio::test(start_paused = true)]
async fn a_valid_message_is_forwarded_to_up_to_three_peers_one_hop_older() {
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    let mut others = Vec::new();
    for seed in 10..15u8 {
        others.push(n.peer(seed).await);
    }
    let envelope = Draft::new(&key(9)).ttl(7).build();
    let id = envelope.message_id().unwrap();

    let action = n.receive(Some(sender), &envelope).await.unwrap();
    after_jitter().await;
    // MUST-020e: F = 3 of the five eligible peers.
    let reached: Vec<&(PeerId, Arc<PipeEnd>)> = others
        .iter()
        .filter(|(_, end)| !gossip_frames(end).is_empty())
        .collect();
    assert_eq!(reached.len(), 3);
    match action {
        GossipAction::Forward { peers } => {
            let mut said = peers.clone();
            said.sort_by_key(|p| p.0);
            let mut got: Vec<PeerId> = reached.iter().map(|(id, _)| *id).collect();
            got.sort_by_key(|p| p.0);
            assert_eq!(said, got);
        }
        other => panic!("{other:?}"),
    }
    assert!(gossip_frames(&sender_end).is_empty());
    for (_, end) in &reached {
        let frames = gossip_frames(end);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        // MUST-020a-c: itself into `seen`, TTL down by one, hops up by one.
        assert!(
            SeenBloomFilter::from_bytes(&f.seen)
                .unwrap()
                .probably_contains(&n.id)
        );
        // MUST-027: the TTL only ever goes down.
        assert_eq!(f.ttl, envelope.ttl - 1);
        assert_eq!(f.hops, envelope.hops + 1);
        // MUST-028: the expiry is the originator's.
        assert_eq!(f.exp, envelope.exp);
        assert_eq!(f.ts, envelope.ts);
        assert_eq!(
            (&f.id, &f.payload, &f.sig),
            (&envelope.id, &envelope.payload, &envelope.sig)
        );
    }
    // MUST-020d: the ID is in the node's deduplication filter.
    assert!(n.gossip.dedup.is_seen(&id));

    // MUST-022: with fewer than three eligible peers, all of them get it.
    let few = node(20);
    let (from, _) = few.peer(2).await;
    let a = few.peer(10).await;
    let b = few.peer(11).await;
    few.receive(Some(from), &Draft::new(&key(9)).build())
        .await
        .unwrap();
    after_jitter().await;
    assert_eq!(gossip_frames(&a.1).len(), 1);
    assert_eq!(gossip_frames(&b.1).len(), 1);
}

#[clause("PNP-005-MUST-021")]
#[tokio::test(start_paused = true)]
async fn forwarding_skips_the_sender_and_peers_already_in_seen() {
    // Twenty rounds: the peer the message came from never gets it back, and neither
    // does a peer the `seen` filter already names; the one remaining peer always does.
    for round in 0..20u8 {
        let n = node(1);
        let (sender, sender_end) = n.peer(2).await;
        let (in_seen, seen_end) = n.peer(3).await;
        let (_, fresh_end) = n.peer(4).await;

        let mut envelope = Draft::new(&key(40 + round)).build();
        let mut seen = SeenBloomFilter::from_bytes(&envelope.seen).unwrap();
        seen.insert(&in_seen);
        envelope.seen = seen.as_bytes().to_vec();

        let action = n.receive(Some(sender), &envelope).await.unwrap();
        after_jitter().await;
        assert!(
            gossip_frames(&sender_end).is_empty(),
            "sent back to its sender"
        );
        assert!(
            gossip_frames(&seen_end).is_empty(),
            "sent to a peer in `seen`"
        );
        assert_eq!(gossip_frames(&fresh_end).len(), 1);
        assert_eq!(
            action,
            GossipAction::Forward {
                peers: vec![identity(4).1]
            }
        );
    }
    // With nobody left to send to, nothing is sent.
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    assert_eq!(
        n.receive(Some(sender), &Draft::new(&key(9)).build())
            .await
            .unwrap(),
        GossipAction::Drop
    );
    after_jitter().await;
    assert!(gossip_frames(&sender_end).is_empty());
}

#[clause("PNP-005-MUST-023", "PNP-005-MUST-024")]
#[tokio::test(start_paused = true)]
async fn each_peer_gets_the_message_after_its_own_random_delay_of_up_to_200_ms() {
    let n = node(1);
    let (sender, _) = n.peer(2).await;
    let ends = [n.peer(10).await.1, n.peer(11).await.1, n.peer(12).await.1];

    let mut delays: Vec<Duration> = Vec::new();
    let mut all_different = 0;
    let rounds = 40usize;
    for round in 0..rounds {
        let envelope = Draft::new(&key(100 + round as u8)).build();
        let received = Instant::now();
        n.receive(Some(sender), &envelope).await.unwrap();
        // Nothing has left yet at the moment of receipt, or only a peer whose delay
        // came out as zero.
        tokio::time::sleep(Duration::from_millis(201)).await;
        let this_round: Vec<Duration> = ends
            .iter()
            .map(|end| {
                let (at, _) = end.sent_at().pop().expect("forwarded to all three");
                at.duration_since(received)
            })
            .collect();
        for end in &ends {
            assert_eq!(gossip_frames(end).len(), round + 1);
        }
        // MUST-023: every delay is within 0 to 200 ms.
        for delay in &this_round {
            assert!(*delay <= Duration::from_millis(200), "{delay:?}");
        }
        // MUST-024: drawn per peer, not once per message.
        if this_round[0] != this_round[1]
            && this_round[1] != this_round[2]
            && this_round[0] != this_round[2]
        {
            all_different += 1;
        }
        delays.extend(this_round);
    }
    // (The timer has millisecond resolution, so two of three peers land on the same
    // millisecond in about one round in seventy.)
    assert!(
        all_different >= rounds - 6,
        "peers share a delay ({all_different}/{rounds})"
    );
    // Uniform over the range, as far as 120 draws show: every 40 ms fifth is hit, and
    // the mean is near 100 ms.
    for fifth in 0..5u64 {
        let lo = Duration::from_millis(fifth * 40);
        let hi = Duration::from_millis(fifth * 40 + 40);
        let hits = delays.iter().filter(|d| **d >= lo && **d < hi).count();
        assert!(
            hits >= 8,
            "{hits} of {} delays in {lo:?}..{hi:?}",
            delays.len()
        );
    }
    let mean = delays.iter().sum::<Duration>() / delays.len() as u32;
    assert!(
        mean > Duration::from_millis(80) && mean < Duration::from_millis(120),
        "{mean:?}"
    );
    // No two messages got the same three delays: the source is not a fixed sequence.
    let triples: std::collections::HashSet<Vec<Duration>> =
        delays.chunks(3).map(|c| c.to_vec()).collect();
    assert_eq!(triples.len(), rounds);
}

// ── §5.3 TTL and expiry at the originator ─────────────────────

#[clause("PNP-005-MUST-025", "PNP-005-MUST-026")]
#[tokio::test(start_paused = true)]
async fn the_originator_sets_ttl_1_to_15_and_at_most_24_hours() {
    let n = node(1);
    let (_, out) = n.peer(2).await;
    let build = |ttl: u8, expiry_secs: u64| {
        n.gossip.build_envelope(
            GROUP,
            b"x".to_vec(),
            GossipParams { ttl, expiry_secs },
            Origin::Identity,
        )
    };

    // MUST-025: 1 to 15, 7 unless said otherwise.
    assert!(build(0, 3600).is_err(), "TTL 0 originated");
    assert!(build(16, 3600).is_err(), "TTL 16 originated");
    assert_eq!(build(1, 3600).unwrap().ttl, 1);
    assert_eq!(build(15, 3600).unwrap().ttl, 15);
    assert_eq!(GossipParams::default().ttl, 7);
    // MUST-026: no more than 86400 seconds ahead.
    assert!(build(7, 86401).is_err(), "25 hours originated");
    let day = build(7, 86400).unwrap();
    assert_eq!(day.exp - day.ts, 86400);
    assert!(day.ts.abs_diff(now_secs()) <= 2);

    // What `publish` sends: TTL 7, 24 hours.
    n.gossip.publish(GROUP, b"default".to_vec()).await.unwrap();
    let sent = gossip_frames(&out).pop().unwrap();
    assert_eq!((sent.ttl, sent.hops), (7, 0));
    assert_eq!(sent.exp - sent.ts, 86400);

    // A receiving node holds others to the same bounds.
    let receiver = node(3);
    let mut long_ttl = Draft::new(&key(9)).build();
    long_ttl.ttl = 16;
    resign(&mut long_ttl, &key(9));
    assert!(receiver.receive(None, &long_ttl).await.is_err());
    let long_life = Draft::new(&key(9)).lifetime(86401).build();
    assert!(receiver.receive(None, &long_life).await.is_err());
    assert!(GossipEnvelope::from_cbor(&long_life.to_cbor().unwrap()).is_err());
    // TTL 15 and exactly 24 hours are fine.
    let edge = Draft::new(&key(9)).ttl(15).lifetime(86400).build();
    assert!(receiver.receive(None, &edge).await.is_ok());
}

// ── §6 Rate limiting ──────────────────────────────────────────

#[clause("PNP-005-MUST-046", "PNP-005-MUST-047", "PNP-005-SHOULD-012")]
#[tokio::test(start_paused = true)]
async fn a_source_gets_10_messages_a_minute_and_the_rest_are_silently_dropped() {
    let n = node(1);
    let (sender, sender_end) = n.peer(2).await;
    let (_, out) = n.peer(3).await;
    let source = key(9);

    // Ten from one source within the minute are taken, whatever `seen` says.
    for i in 0..10 {
        let mut e = Draft::new(&source).build();
        if i % 2 == 0 {
            e.seen = vec![0u8; 128]; // a relay cleared the filter on the way
        }
        let outcome = n.receive(Some(sender), &e).await.unwrap();
        assert!(
            matches!(outcome, GossipAction::Forward { .. }),
            "message {i}: {outcome:?}"
        );
    }
    // The eleventh and twelfth are not.
    for _ in 0..2 {
        let outcome = n
            .receive(Some(sender), &Draft::new(&source).build())
            .await
            .unwrap();
        assert_eq!(outcome, GossipAction::RateLimited);
    }
    after_jitter().await;
    // MUST-047: dropped (not forwarded) and silently (nothing to the sender, and the
    // peer that relayed them is not blamed for what the source did).
    assert_eq!(gossip_frames(&out).len(), 10);
    assert!(sender_end.sent().is_empty());
    assert_eq!(n.score(&sender).await, 110);

    // The limit is per source: another one is unaffected.
    assert!(matches!(
        n.receive(Some(sender), &Draft::new(&key(10)).build())
            .await
            .unwrap(),
        GossipAction::Forward { .. }
    ));
    // And per 60 seconds: after the window the first source is heard again.
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert_eq!(
        n.receive(Some(sender), &Draft::new(&source).build())
            .await
            .unwrap(),
        GossipAction::RateLimited
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(matches!(
        n.receive(Some(sender), &Draft::new(&source).build())
            .await
            .unwrap(),
        GossipAction::Forward { .. }
    ));
}

#[clause("PNP-005-MUST-046")]
#[tokio::test(start_paused = true)]
async fn messages_that_only_claim_a_source_do_not_use_up_its_allowance() {
    let n = node(1);
    let (attacker, _) = n.peer(2).await;
    let (honest, _) = n.peer(4).await;
    let (_, out) = n.peer(3).await;
    let victim = key(9);

    // Twenty messages naming the victim as source, none of them signed by it.
    for _ in 0..20 {
        let mut forged = Draft::new(&victim).difficulty(0).build();
        forged.sig = vec![0x11; 64];
        assert!(n.receive(Some(attacker), &forged).await.is_err());
        if !n.pool.is_connected(&attacker).await {
            break; // by now the attacker has been thrown out
        }
    }
    // The victim's own messages still pass, all ten of its allowance.
    for i in 0..10 {
        let outcome = n
            .receive(Some(honest), &Draft::new(&victim).build())
            .await
            .unwrap();
        assert!(
            matches!(outcome, GossipAction::Forward { .. }),
            "message {i}: {outcome:?}"
        );
    }
    after_jitter().await;
    assert_eq!(gossip_frames(&out).len(), 10);

    // Anonymous user messages have no source PeerId to count against; the peer that
    // delivers them is counted instead, so one peer cannot exhaust everyone's.
    let n = node(5);
    let (flooder, _) = n.peer(2).await;
    let (quiet, _) = n.peer(4).await;
    for _ in 0..10 {
        let e = Draft::new(&key(9)).anonymous().build();
        assert!(n.receive(Some(flooder), &e).await.is_ok());
    }
    let e = Draft::new(&key(9)).anonymous().build();
    assert_eq!(
        n.receive(Some(flooder), &e).await.unwrap(),
        GossipAction::RateLimited
    );
    let e = Draft::new(&key(9)).anonymous().build();
    assert_ne!(
        n.receive(Some(quiet), &e).await.unwrap(),
        GossipAction::RateLimited
    );
}

// ── §5.6 Difficulty adjustment ────────────────────────────────

#[clause("PNP-005-SHOULD-006")]
#[tokio::test(start_paused = true)]
async fn a_node_adopts_the_median_difficulty_its_relays_advertise() {
    let n = node(1);
    assert_eq!(n.gossip.required_difficulty(USER), 16);

    // Three relays advertise 17, 19 and 18 in their descriptors.
    for (seed, advertised) in [(50u8, 17u8), (51, 19), (52, 18)] {
        let payload = RelayDescriptorGossip {
            descriptor: vec![seed],
            pow_difficulty: Some(advertised),
        }
        .to_cbor()
        .unwrap();
        let descriptor = Draft::new(&key(seed))
            .payload_type(DESCRIPTOR)
            .payload(payload)
            .lifetime(21600)
            .difficulty(20)
            .build();
        assert!(n.receive(None, &descriptor).await.is_ok());
    }
    // The median, 18, is what the node now asks for and works to.
    assert_eq!(n.gossip.required_difficulty(USER), 18);
    assert_eq!(n.gossip.required_difficulty(GROUP), 18);
    // Relay descriptors keep their own, higher floor.
    assert_eq!(n.gossip.required_difficulty(DESCRIPTOR), 20);

    let sixteen = underpowered(&key(9), GROUP, 16, 18);
    assert!(pow_zero_bits(&sixteen) >= 16);
    assert!(matches!(
        n.receive(None, &sixteen).await,
        Err(MeshError::InsufficientPoW)
    ));
    let eighteen = Draft::new(&key(9))
        .payload_type(GROUP)
        .difficulty(18)
        .build();
    assert!(n.receive(None, &eighteen).await.is_ok());
    let own = n
        .gossip
        .build_envelope(
            GROUP,
            b"x".to_vec(),
            GossipParams::default(),
            Origin::Identity,
        )
        .unwrap();
    assert!(pow_zero_bits(&own) >= 18);

    // Relays cannot talk the network below the spec's floor.
    let low = node(2);
    for seed in [60u8] {
        let payload = RelayDescriptorGossip {
            descriptor: vec![seed],
            pow_difficulty: Some(2),
        }
        .to_cbor()
        .unwrap();
        let descriptor = Draft::new(&key(seed))
            .payload_type(DESCRIPTOR)
            .payload(payload)
            .lifetime(21600)
            .difficulty(20)
            .build();
        low.receive(None, &descriptor).await.unwrap();
    }
    assert_eq!(low.gossip.required_difficulty(USER), 16);
}
