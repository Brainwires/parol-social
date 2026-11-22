//! PNP-004 conformance: relay descriptors (§5.6) and relay selection (§5.7).

mod inproc;

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use inproc::{identity, now_secs};
use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::RelayDescriptorGossip;
use parolnet_relay::RelayError;
use parolnet_relay::capabilities::{self, EXIT_ALLOWED, EXIT_GOSSIP};
use parolnet_relay::directory::{
    DESCRIPTOR_REFRESH_SECS, GUARD_MIN_UPTIME_SECS, GUARD_SET_LIFETIME_SECS,
    MAX_DESCRIPTOR_AGE_SECS, MIN_DESCRIPTORS, RelayDescriptor, RelayDirectory, Subnet, subnet_of,
};
use parolnet_relay::publish::{DescriptorGossip, DescriptorPublisher, ingest_descriptor_gossip};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const DAY: u64 = 86400;

/// A change to one field of a descriptor.
type Mutation = Box<dyn Fn(&mut RelayDescriptor)>;

/// A signed descriptor for relay `index` at `addr`.
fn signed(
    index: u16,
    addr: &str,
    uptime_secs: u64,
    capabilities: u8,
    timestamp: u64,
) -> RelayDescriptor {
    let mut seed = [0x5Au8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    RelayDirectory::create_descriptor(
        PeerId::from_public_key(&public),
        public,
        [index as u8; 32],
        addr.parse().unwrap(),
        capabilities,
        uptime_secs,
        timestamp,
        &key,
    )
}

/// A relay in its own /16, signed and fresh.
fn relay(index: u16, uptime_days: u64) -> RelayDescriptor {
    let addr = format!("10.{}.{}.1:9001", index % 256, index / 256);
    signed(index, &addr, uptime_days * DAY, 1, now_secs())
}

// ── §5.6 Descriptors ──────────────────────────────────────────

#[clause("PNP-004-MUST-041")]
#[test]
fn a_relay_descriptor_carries_every_field_under_its_signature() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let public = key.verifying_key().to_bytes();
    let now = now_secs();
    for addr in ["203.0.113.7:443", "[2001:db8:7::1]:9001"] {
        let publisher = DescriptorPublisher::new(
            key.clone(),
            [9u8; 32],
            addr.parse().unwrap(),
            capabilities::pack(3, EXIT_ALLOWED | EXIT_GOSSIP),
        )
        .with_prior_uptime(10 * DAY);
        let d = publisher.descriptor(now);

        // PeerId, identity key, X25519 key, address, capabilities, uptime, timestamp.
        assert_eq!(d.peer_id.0, <[u8; 32]>::from(Sha256::digest(public)));
        assert_eq!(d.identity_key, public);
        assert_eq!(d.x25519_key, [9u8; 32]);
        assert_eq!(d.addr, addr.parse::<SocketAddr>().unwrap());
        assert_eq!(capabilities::bandwidth_class(d.bandwidth_class), 3);
        assert_eq!(
            capabilities::exit_flags(d.bandwidth_class),
            EXIT_ALLOWED | EXIT_GOSSIP
        );
        assert!(d.uptime_secs >= 10 * DAY);
        assert_eq!(d.timestamp, now);

        // The Ed25519 signature is the identity key's, over all of them: change any one
        // and it no longer verifies.
        assert!(d.verify_self_signature());
        let mutations: Vec<(&str, Mutation)> = vec![
            ("peer id", Box::new(|d| d.peer_id.0[0] ^= 1)),
            ("identity key", Box::new(|d| d.identity_key[0] ^= 1)),
            ("x25519 key", Box::new(|d| d.x25519_key[0] ^= 1)),
            ("port", Box::new(|d| d.addr.set_port(d.addr.port() + 1))),
            (
                "address",
                Box::new(|d| d.addr = "198.51.100.1:443".parse().unwrap()),
            ),
            ("bandwidth class", Box::new(|d| d.bandwidth_class ^= 0x01)),
            (
                "exit policy",
                Box::new(|d| d.bandwidth_class ^= EXIT_ALLOWED),
            ),
            ("uptime", Box::new(|d| d.uptime_secs += 1)),
            ("timestamp", Box::new(|d| d.timestamp += 1)),
            ("signature", Box::new(|d| d.signature[5] ^= 1)),
        ];
        for (field, mutate) in mutations {
            let mut changed = d.clone();
            mutate(&mut changed);
            assert!(
                !changed.verify_self_signature(),
                "a descriptor with a changed {field} still verifies"
            );
        }

        // What the relay publishes is this descriptor.
        let payload = publisher.gossip_payload(now).unwrap();
        let wrapper = RelayDescriptorGossip::from_cbor(&payload).unwrap();
        let published: RelayDescriptor =
            ciborium::from_reader(wrapper.descriptor.as_slice()).unwrap();
        assert!(published.verify_self_signature());
        assert_eq!(published.signable_bytes(), d.signable_bytes());
    }
}

struct RecordingGossip {
    published: Mutex<Vec<(Instant, Vec<u8>)>>,
}

#[async_trait]
impl DescriptorGossip for RecordingGossip {
    async fn publish_descriptor(&self, payload: Vec<u8>) -> Result<(), RelayError> {
        self.published
            .lock()
            .unwrap()
            .push((Instant::now(), payload));
        Ok(())
    }
}

#[clause("PNP-004-MUST-043")]
#[tokio::test(start_paused = true)]
async fn a_relay_refreshes_its_descriptor_at_least_every_six_hours() {
    assert_eq!(DESCRIPTOR_REFRESH_SECS, 6 * 3600);
    let publisher = Arc::new(DescriptorPublisher::new(
        SigningKey::from_bytes(&[8u8; 32]),
        [1u8; 32],
        "203.0.113.8:443".parse().unwrap(),
        capabilities::pack(1, 0),
    ));
    let gossip = Arc::new(RecordingGossip {
        published: Mutex::new(Vec::new()),
    });
    let started = Instant::now();
    let task = publisher.spawn(gossip.clone());
    tokio::time::sleep(Duration::from_secs(25 * 3600)).await;
    task.abort();

    let published = gossip.published.lock().unwrap().clone();
    // At start, and then never more than six hours apart.
    assert!(
        published.len() >= 5,
        "{} descriptors in 25 hours",
        published.len()
    );
    assert!(published[0].0.duration_since(started) < Duration::from_secs(1));
    for pair in published.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            gap <= Duration::from_secs(6 * 3600),
            "{gap:?} between two descriptors"
        );
    }
    // Each one is a new descriptor: later uptime, its own signature.
    let descriptors: Vec<RelayDescriptor> = published
        .iter()
        .map(|(_, payload)| {
            let wrapper = RelayDescriptorGossip::from_cbor(payload).unwrap();
            ciborium::from_reader(wrapper.descriptor.as_slice()).unwrap()
        })
        .collect();
    for pair in descriptors.windows(2) {
        assert!(pair[1].uptime_secs > pair[0].uptime_secs);
        assert_ne!(pair[1].signature, pair[0].signature);
        assert!(pair[1].verify_self_signature());
    }
}

#[clause("PNP-004-MUST-044")]
#[test]
fn a_descriptor_is_accepted_only_with_a_valid_signature_and_matching_peer_id() {
    let now = now_secs();
    let mut dir = RelayDirectory::new();

    let good = relay(1, 8);
    assert!(dir.handle_gossip_descriptor(good.clone(), now));
    assert_eq!(dir.lookup_addr(&good.peer_id), Some(good.addr));

    // A broken signature.
    let mut bad_sig = relay(2, 8);
    bad_sig.signature[0] ^= 1;
    assert!(!dir.handle_gossip_descriptor(bad_sig.clone(), now));
    assert!(dir.lookup_addr(&bad_sig.peer_id).is_none());

    // A field changed after signing.
    let mut moved = relay(3, 8);
    moved.addr = "198.51.100.9:1".parse().unwrap();
    assert!(!dir.handle_gossip_descriptor(moved, now));

    // A valid signature by some key, over a descriptor that claims relay 1's PeerId:
    // PeerId is not SHA-256 of the identity key in it.
    let attacker = SigningKey::from_bytes(&[0xA7; 32]);
    let mut impostor = relay(4, 8);
    impostor.identity_key = attacker.verifying_key().to_bytes();
    impostor.peer_id = good.peer_id;
    impostor.addr = "198.51.100.66:9001".parse().unwrap();
    impostor.timestamp = now + 1;
    impostor.signature = attacker.sign(&impostor.signable_bytes()).to_bytes();
    assert!(!dir.handle_gossip_descriptor(impostor.clone(), now + 1));
    assert_eq!(
        dir.lookup_addr(&good.peer_id),
        Some(good.addr),
        "relay 1 was replaced"
    );
    assert_eq!(dir.len(), 1);

    // Over gossip, the message has to come from the relay the descriptor describes.
    let fresh = relay(5, 8);
    let mut cbor = Vec::new();
    ciborium::into_writer(&fresh, &mut cbor).unwrap();
    let payload = RelayDescriptorGossip {
        descriptor: cbor,
        pow_difficulty: None,
    }
    .to_cbor()
    .unwrap();
    assert!(!ingest_descriptor_gossip(
        &mut dir,
        &identity(9).1,
        &payload,
        now
    ));
    assert!(ingest_descriptor_gossip(
        &mut dir,
        &fresh.peer_id,
        &payload,
        now
    ));
    assert_eq!(dir.len(), 2);
    assert!(!ingest_descriptor_gossip(
        &mut dir,
        &fresh.peer_id,
        b"not cbor",
        now
    ));
}

#[clause("PNP-004-SHOULD-002")]
#[test]
fn descriptors_older_than_24_hours_are_not_used_for_new_circuits() {
    let now = now_secs();
    assert_eq!(MAX_DESCRIPTOR_AGE_SECS, 24 * 3600);

    // Not accepted from gossip at 24 hours; accepted just under.
    let mut dir = RelayDirectory::new();
    let old = signed(1, "10.1.0.1:9001", 8 * DAY, 1, now - 24 * 3600);
    let nearly = signed(2, "10.2.0.1:9001", 8 * DAY, 1, now - 24 * 3600 + 60);
    assert!(!dir.handle_gossip_descriptor(old, now));
    assert!(dir.handle_gossip_descriptor(nearly, now));

    // Three fresh relays and three that went stale while held: only the fresh ones are
    // ever on a path.
    let mut dir = RelayDirectory::new();
    let mut stale = HashSet::new();
    for i in 1..=3u16 {
        dir.insert(relay(i, 8));
        let aged = signed(
            10 + i,
            &format!("10.{}.0.1:9001", 10 + i),
            8 * DAY,
            9,
            now - 25 * 3600,
        );
        stale.insert(aged.peer_id);
        dir.insert(aged);
    }
    for _ in 0..200 {
        let path = dir.select_path().expect("three fresh relays make a path");
        assert!(path.iter().all(|hop| !stale.contains(&hop.peer_id)));
    }
    // With too few fresh ones there is no path, however many stale ones there are.
    let mut dir = RelayDirectory::new();
    dir.insert(relay(1, 8));
    dir.insert(relay(2, 8));
    for i in 3..=8u16 {
        dir.insert(signed(
            i,
            &format!("10.{i}.0.1:9001"),
            8 * DAY,
            1,
            now - 25 * 3600,
        ));
    }
    assert!(dir.select_path().is_none());
}

#[clause("PNP-004-SHOULD-003")]
#[test]
fn the_directory_keeps_well_over_100_descriptors() {
    let now = now_secs();
    assert_eq!(MIN_DESCRIPTORS, 100);
    let mut dir = RelayDirectory::new();
    for i in 1..=180u16 {
        assert!(dir.handle_gossip_descriptor(relay(i, 8), now));
    }
    assert_eq!(dir.len(), 180);
    assert!(dir.len() >= MIN_DESCRIPTORS);
    // Housekeeping removes what is stale and nothing else.
    dir.prune_stale(now + 3600);
    assert_eq!(dir.len(), 180);
    for i in 1..=180u16 {
        assert!(dir.lookup_addr(&relay(i, 8).peer_id).is_some());
    }
    // Selection still works over the whole cache.
    assert!(dir.select_path().is_some());
}

// ── §5.7 Relay selection ──────────────────────────────────────

#[clause("PNP-004-MUST-045", "PNP-004-MUST-046")]
#[test]
fn hop_1_is_a_guard_and_hops_2_and_3_are_random_other_relays() {
    let now = now_secs();
    let mut dir = RelayDirectory::new();
    for i in 1..=4u16 {
        dir.insert(relay(i, 8)); // up long enough to be guards
    }
    for i in 5..=12u16 {
        dir.insert(relay(i, 1));
    }

    let mut middles = HashSet::new();
    let mut exits = HashSet::new();
    let mut firsts = HashSet::new();
    for _ in 0..400 {
        let path = dir.select_path().expect("a path");
        let guards: Vec<PeerId> = dir.guard_set(now).iter().map(|g| g.peer_id).collect();
        // MUST-045: hop 1 comes from the guard set.
        assert!(guards.contains(&path[0].peer_id), "hop 1 is not a guard");
        // MUST-046: hops 2 and 3 are neither the guard nor each other.
        assert_ne!(path[1].peer_id, path[0].peer_id);
        assert_ne!(path[2].peer_id, path[0].peer_id);
        assert_ne!(path[1].peer_id, path[2].peer_id);
        firsts.insert(path[0].peer_id);
        middles.insert(path[1].peer_id);
        exits.insert(path[2].peer_id);
    }
    // Hop 1 never leaves the guard set (three relays at most).
    assert!(firsts.len() <= 3);
    // Hops 2 and 3 range over the pool: 11 candidates each, nearly all of them seen.
    assert!(
        middles.len() >= 9,
        "hop 2 took only {} relays",
        middles.len()
    );
    assert!(exits.len() >= 9, "hop 3 took only {} relays", exits.len());

    // Without any relay fit to be a guard there is no path.
    let mut young = RelayDirectory::new();
    for i in 1..=6u16 {
        young.insert(relay(i, 1));
    }
    assert!(young.select_path().is_none());
}

#[clause("PNP-004-MUST-047")]
#[test]
fn no_two_hops_share_a_16_or_a_48() {
    let now = now_secs();
    let put = |dir: &mut RelayDirectory, index: u16, addr: &str| {
        dir.insert(signed(index, addr, 8 * DAY, 1, now));
    };

    // IPv4: a /16 holds at most one hop. Five relays in one /16, then in two: no path.
    let mut dir = RelayDirectory::new();
    for i in 1..=5u16 {
        put(&mut dir, i, &format!("10.1.{i}.1:9001"));
    }
    assert!(dir.select_path().is_none(), "three hops in one /16");
    for i in 6..=9u16 {
        put(&mut dir, i, &format!("10.2.{i}.1:9001"));
    }
    assert!(dir.select_path().is_none(), "three hops in two /16s");
    // A third /16 makes it possible, and then each hop is in another.
    put(&mut dir, 10, "10.3.0.1:9001");
    for _ in 0..200 {
        let path = dir.select_path().expect("three /16s");
        let nets: HashSet<[u8; 2]> = path
            .iter()
            .map(|h| match subnet_of(&h.addr) {
                Subnet::V4(n) => n,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(nets.len(), 3);
    }
    // Same /8, different /16: allowed. Same /16, different /24: not.
    assert_ne!(
        subnet_of(&"10.1.0.1:1".parse().unwrap()),
        subnet_of(&"10.2.0.1:1".parse().unwrap())
    );
    assert_eq!(
        subnet_of(&"10.1.0.1:1".parse().unwrap()),
        subnet_of(&"10.1.200.9:1".parse().unwrap())
    );

    // IPv6: the unit is the /48.
    let mut dir = RelayDirectory::new();
    for i in 1..=5u16 {
        put(&mut dir, i, &format!("[2001:db8:1:{i}::1]:9001"));
    }
    assert!(dir.select_path().is_none(), "three hops in one /48");
    // Same /32, three different /48s: a path.
    put(&mut dir, 6, "[2001:db8:2::1]:9001");
    put(&mut dir, 7, "[2001:db8:3::1]:9001");
    for _ in 0..200 {
        let path = dir.select_path().expect("three /48s");
        let nets: HashSet<Subnet> = path.iter().map(|h| subnet_of(&h.addr)).collect();
        assert_eq!(nets.len(), 3);
        assert!(nets.iter().all(|n| matches!(n, Subnet::V6(_))));
    }
    // An IPv4-mapped IPv6 address is in its IPv4 /16.
    assert_eq!(
        subnet_of(&"[::ffff:10.1.0.5]:1".parse().unwrap()),
        subnet_of(&"10.1.9.9:1".parse().unwrap())
    );
    // `select_random` on its own holds to it too: nothing from an excluded relay's net.
    let mut dir = RelayDirectory::new();
    put(&mut dir, 1, "10.1.0.1:9001");
    put(&mut dir, 2, "10.1.0.2:9001");
    let first = signed(1, "10.1.0.1:9001", 8 * DAY, 1, now).peer_id;
    assert!(dir.select_random(&[first]).is_none());
    put(&mut dir, 3, "10.9.0.1:9001");
    for _ in 0..50 {
        let pick = dir.select_random(&[first]).unwrap();
        assert_eq!(pick.addr, "10.9.0.1:9001".parse::<SocketAddr>().unwrap());
    }
}

#[clause("PNP-004-SHOULD-004")]
#[test]
fn the_guard_set_is_2_to_3_long_lived_relays_and_stays_for_30_days() {
    let now = now_secs();
    assert_eq!(GUARD_MIN_UPTIME_SECS, 7 * DAY);
    assert_eq!(GUARD_SET_LIFETIME_SECS, 30 * DAY);

    let populate = |dir: &mut RelayDirectory, stamp: u64| {
        for i in 1..=12u16 {
            let addr = format!("10.{i}.0.1:9001");
            // 1-4: up 6 days. 5: up exactly 7 days. 6-12: up more than 7 days.
            let uptime = match i {
                1..=4 => 6 * DAY,
                5 => 7 * DAY,
                _ => 7 * DAY + i as u64 * 3600,
            };
            dir.insert(signed(i, &addr, uptime, 1, stamp));
        }
    };
    let eligible: HashSet<PeerId> = (6..=12u16)
        .map(|i| signed(i, &format!("10.{i}.0.1:9001"), 0, 1, 0).peer_id)
        .collect();

    let mut dir = RelayDirectory::new();
    populate(&mut dir, now);
    let set: Vec<PeerId> = dir.guard_set(now).iter().map(|g| g.peer_id).collect();
    // Two to three relays, each up for more than seven days.
    assert_eq!(set.len(), 3);
    assert!(
        set.iter().all(|g| eligible.contains(g)),
        "a guard with too little uptime"
    );
    assert_eq!(set.iter().collect::<HashSet<_>>().len(), 3);

    // Building paths does not shrink or reshuffle it, and it holds for 30 days
    // (descriptors are refreshed along the way, as they are in a live directory).
    for day in 0..30u64 {
        let at = now + day * DAY;
        populate(&mut dir, at);
        for _ in 0..5 {
            let path = dir.select_path_at(at, &[]).expect("a path");
            assert!(set.contains(&path[0].peer_id));
        }
        let again: Vec<PeerId> = dir.guard_set(at).iter().map(|g| g.peer_id).collect();
        assert_eq!(again, set, "the guard set changed on day {day}");
    }
    assert_eq!(dir.select_guards(3).len(), 3);
    assert_eq!(dir.select_guards(2).len(), 2);

    // After 30 days it is chosen anew. Seven candidates: over several periods the same
    // three in the same order every time would be a 1-in-210 event each.
    let mut changed = false;
    let mut at = now;
    let mut current = set;
    for _ in 0..6 {
        at += 30 * DAY;
        populate(&mut dir, at);
        let next: Vec<PeerId> = dir.guard_set(at).iter().map(|g| g.peer_id).collect();
        assert_eq!(next.len(), 3);
        assert!(next.iter().all(|g| eligible.contains(g)));
        changed |= next != current;
        current = next;
    }
    assert!(
        changed,
        "the guard set never changed across six 30-day periods"
    );

    // With only two relays fit to be guards the set is those two.
    let mut small = RelayDirectory::new();
    small.insert(relay(1, 8));
    small.insert(relay(2, 9));
    small.insert(relay(3, 2));
    assert_eq!(small.guard_set(now).len(), 2);
}

#[clause("PNP-004-SHOULD-005")]
#[test]
fn selection_is_weighted_by_advertised_bandwidth_class() {
    let now = now_secs();
    let mut dir = RelayDirectory::new();
    // Two relays, alike but for the bandwidth class they advertise: 0 and 9.
    let slow = signed(
        1,
        "10.1.0.1:9001",
        DAY,
        capabilities::pack(0, EXIT_ALLOWED),
        now,
    );
    let fast = signed(
        2,
        "10.2.0.1:9001",
        DAY,
        capabilities::pack(9, EXIT_ALLOWED),
        now,
    );
    let fast_id = fast.peer_id;
    dir.insert(slow);
    dir.insert(fast);

    let picks = 4000;
    let fast_picks = (0..picks)
        .filter(|_| dir.select_random(&[]).unwrap().peer_id == fast_id)
        .count();
    let slow_picks = picks - fast_picks;
    assert!(slow_picks > 0, "the slow relay is never chosen");
    // Class 9 against class 0 is ten to one; anything under five to one is not weighting.
    assert!(
        fast_picks > 5 * slow_picks,
        "fast {fast_picks} : slow {slow_picks}"
    );
}
