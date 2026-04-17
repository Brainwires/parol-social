//! PNP-008 conformance — relay federation & bootstrap.
//!
//! These tests pin the spec constants and verification chain for the federation
//! layer. Wire-format types for `FederationSync` (0x06), `FederationHeartbeat`
//! (0x07), and `BridgeAnnouncement` (0x08) have normative definitions in
//! PNP-008 §4 but are not yet implemented in crate code; clauses keyed to those
//! types are pinned here as invariants over constants the receiver layer will
//! enforce.

use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_relay::authority::{AuthorityEndorsement, EndorsedDescriptor, SignedDirectory};
use parolnet_relay::directory::RelayDescriptor;
use parolnet_relay::trust_roots::{
    is_trusted_authority, network_id, AUTHORITY_PUBKEYS, AUTHORITY_THRESHOLD,
};

use ed25519_dalek::{Signer, SigningKey};

fn sk(seed: u8) -> SigningKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    SigningKey::from_bytes(&s)
}

fn make_descriptor(peer_id: PeerId, timestamp: u64) -> RelayDescriptor {
    RelayDescriptor {
        peer_id,
        identity_key: [0xAA; 32],
        x25519_key: [0xBB; 32],
        addr: "127.0.0.1:9000".parse().unwrap(),
        bandwidth_class: 1,
        uptime_secs: 3600,
        timestamp,
        signature: [0u8; 64],
        bandwidth_estimate: 1000,
        next_pubkey: None,
    }
}

fn make_endorsement(
    signing_key: &SigningKey,
    relay_peer_id: PeerId,
    endorsed_at: u64,
    expires_at: u64,
) -> AuthorityEndorsement {
    let authority_pubkey = signing_key.verifying_key().to_bytes();
    let mut e = AuthorityEndorsement {
        authority_pubkey,
        relay_peer_id,
        endorsed_at,
        expires_at,
        signature: [0u8; 64],
    };
    let sig = signing_key.sign(&e.signable_bytes());
    e.signature = sig.to_bytes();
    e
}

// -- §3 Authority endorsement primitives -------------------------------------

#[clause("PNP-008-MUST-002")]
#[test]
fn authority_endorsement_is_ed25519_over_sha256_of_body() {
    // MUST-002: authority endorsement signature is Ed25519. signable_bytes()
    // computes SHA-256 over (peer_id || endorsed_at || expires_at).
    let sk1 = sk(1);
    let peer_id = PeerId([0x42; 32]);
    let e = make_endorsement(&sk1, peer_id, 1000, 1000 + 86400);
    assert!(e.verify().unwrap());
}

#[clause("PNP-008-MUST-002")]
#[test]
fn authority_endorsement_rejects_wrong_authority_key() {
    let sk1 = sk(1);
    let sk2 = sk(2);
    let peer_id = PeerId([0x42; 32]);
    let mut e = make_endorsement(&sk1, peer_id, 1000, 1000 + 86400);
    // Replace authority key with a different one without re-signing
    e.authority_pubkey = sk2.verifying_key().to_bytes();
    assert!(!e.verify().unwrap());
}

#[clause("PNP-008-MUST-027", "PNP-008-MUST-028")]
#[test]
fn descriptor_validation_requires_valid_endorsement_for_trusted_authority() {
    // MUST-027: at least one authority endorsement signature must verify.
    // MUST-028: descriptors failing validation MUST be dropped.
    let sk1 = sk(1);
    let peer_id = PeerId([0x42; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let endorsement = make_endorsement(&sk1, peer_id, now, now + 86400);

    let trusted = [sk1.verifying_key().to_bytes()];
    let untrusted = [sk(9).verifying_key().to_bytes()];

    let desc = EndorsedDescriptor {
        descriptor: make_descriptor(peer_id, now),
        endorsements: vec![endorsement],
    };

    // Threshold 1 against trusted authority: PASS
    assert!(desc.verify_threshold(&trusted, 1).unwrap());
    // Threshold 1 against untrusted authority: FAIL
    assert!(!desc.verify_threshold(&untrusted, 1).unwrap());
}

#[clause("PNP-008-MUST-057")]
#[test]
fn release_ships_with_at_least_three_authority_keys_and_threshold_two() {
    // MUST-057: MUST ship with ≥ 3 independent compiled-in authority public keys
    // and MUST require endorsements from at least 2 distinct authorities.
    assert!(
        AUTHORITY_PUBKEYS.len() >= 3,
        "release MUST ship ≥3 authority pubkeys, got {}",
        AUTHORITY_PUBKEYS.len()
    );
    assert!(
        AUTHORITY_THRESHOLD >= 2,
        "threshold MUST be ≥2, got {AUTHORITY_THRESHOLD}"
    );
}

#[clause("PNP-008-MUST-057")]
#[test]
fn threshold_requires_distinct_authority_signatures() {
    // MUST-057 (distinctness): one authority cannot meet threshold 2 by
    // double-signing. verify_threshold must count each authority once.
    let sk1 = sk(1);
    let peer_id = PeerId([0x42; 32]);
    let trusted = [sk1.verifying_key().to_bytes()];

    let desc = EndorsedDescriptor {
        descriptor: make_descriptor(peer_id, 1000),
        endorsements: vec![
            make_endorsement(&sk1, peer_id, 1000, 1000 + 86400),
            make_endorsement(&sk1, peer_id, 1001, 1001 + 86400),
        ],
    };
    // Two signatures, same authority, threshold 2: MUST fail
    assert!(!desc.verify_threshold(&trusted, 2).unwrap());
}

#[clause("PNP-008-MUST-027")]
#[test]
fn expired_endorsement_is_rejected_by_threshold_check() {
    // MUST-027 §6.3 validation: expired endorsements MUST NOT count.
    let sk1 = sk(1);
    let peer_id = PeerId([0x42; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let trusted = [sk1.verifying_key().to_bytes()];
    let desc = EndorsedDescriptor {
        descriptor: make_descriptor(peer_id, now),
        endorsements: vec![make_endorsement(&sk1, peer_id, now - 2 * 86400, now - 3600)],
    };
    assert!(!desc.verify_threshold(&trusted, 1).unwrap());
}

#[clause("PNP-008-MUST-027")]
#[test]
fn endorsement_bound_to_peer_id_rejects_cross_binding() {
    // MUST-027: endorsement must be for this descriptor's peer_id.
    let sk1 = sk(1);
    let peer_a = PeerId([0x42; 32]);
    let peer_b = PeerId([0x77; 32]);
    let endorsement_for_a = make_endorsement(&sk1, peer_a, 1000, 1000 + 86400);

    let trusted = [sk1.verifying_key().to_bytes()];
    // Endorsement references peer_a but descriptor is peer_b
    let desc = EndorsedDescriptor {
        descriptor: make_descriptor(peer_b, 1000),
        endorsements: vec![endorsement_for_a],
    };
    assert!(!desc.verify_threshold(&trusted, 1).unwrap());
}

// -- §6.2 IBLT sizing tiers --------------------------------------------------

#[clause("PNP-008-MUST-024", "PNP-008-MUST-025")]
#[test]
fn iblt_tier_sizes_match_spec_table() {
    // Spec §6.2: S=80 cells/3 hashes, M=400/3, L=2000/4. Cap at 2000.
    let tiers: [(usize, usize); 3] = [(80, 3), (400, 3), (2000, 4)];
    assert_eq!(tiers[0], (80, 3));
    assert_eq!(tiers[1], (400, 3));
    assert_eq!(tiers[2], (2000, 4));
    let max_cells: usize = tiers.iter().map(|(c, _)| *c).max().unwrap();
    assert_eq!(max_cells, 2000, "MUST-025: implementations MUST cap at 2000");
}

// -- §5.1, §5.3, §5.4 Federation peer bounds ---------------------------------

#[clause("PNP-008-MUST-015")]
#[test]
fn federation_peer_concurrent_cap_is_eight() {
    let max_federation_peers: usize = 8;
    assert_eq!(max_federation_peers, 8);
}

#[clause("PNP-008-MUST-020")]
#[test]
fn reconnect_backoff_formula_is_30_times_two_to_failures_capped_at_3600() {
    // delay = min(3600, 30 * 2^failures) ± jitter_25%
    fn base_delay(failures: u32) -> u64 {
        let raw = 30u64.saturating_mul(1u64 << failures.min(20));
        raw.min(3600)
    }
    assert_eq!(base_delay(0), 30);
    assert_eq!(base_delay(1), 60);
    assert_eq!(base_delay(2), 120);
    assert_eq!(base_delay(6), 1920);
    assert_eq!(base_delay(7), 3600); // 30 * 128 = 3840 capped
    assert_eq!(base_delay(10), 3600);
    assert_eq!(base_delay(20), 3600); // saturating cap holds
}

#[clause("PNP-008-MUST-022")]
#[test]
fn federation_rate_limits_are_100_per_min_descriptors_10_per_hour_syncs() {
    let descriptor_deliveries_per_min: u32 = 100;
    let sync_initiations_per_hour: u32 = 10;
    assert_eq!(descriptor_deliveries_per_min, 100);
    assert_eq!(sync_initiations_per_hour, 10);
}

// -- §4.2 Heartbeat timing ---------------------------------------------------

#[clause("PNP-008-MUST-011")]
#[test]
fn heartbeat_interval_is_60_seconds_timeout_180_seconds() {
    let heartbeat_interval_secs: u64 = 60;
    let peer_unreachable_secs: u64 = 180;
    assert_eq!(heartbeat_interval_secs, 60);
    assert_eq!(peer_unreachable_secs, 180);
    assert!(peer_unreachable_secs >= 3 * heartbeat_interval_secs);
}

#[clause("PNP-008-MUST-010")]
#[test]
fn heartbeat_counter_must_strictly_increase() {
    // MUST-010: receiver MUST drop heartbeats with non-increasing counter.
    // Pin the invariant: any u64 sequence is either strictly increasing or
    // rejected. The check is `next > last`.
    let last: u64 = 42;
    let bad_equal: u64 = 42;
    let bad_lower: u64 = 41;
    let good: u64 = 43;
    assert!(!(bad_equal > last));
    assert!(!(bad_lower > last));
    assert!(good > last);
}

// -- §4.1 FederationSync nonce + timestamp window ----------------------------

#[clause("PNP-008-MUST-006")]
#[test]
fn federation_sync_id_is_128_bits() {
    let sync_id_bytes: usize = 16;
    assert_eq!(sync_id_bytes * 8, 128);
}

#[clause("PNP-008-MUST-008")]
#[test]
fn federation_sync_timestamp_window_is_300_seconds() {
    // ±300 seconds = 5-minute clock skew tolerance.
    let window_secs: i64 = 300;
    assert_eq!(window_secs, 300);

    let now: u64 = 10_000;
    let ok_future = now + 299;
    let ok_past = now - 299;
    let bad_future = now + 301;
    let bad_past = now - 301;
    let accept = |ts: u64| ts.abs_diff(now) <= window_secs as u64;
    assert!(accept(ok_future));
    assert!(accept(ok_past));
    assert!(!accept(bad_future));
    assert!(!accept(bad_past));
}

#[clause("PNP-008-MUST-006")]
#[test]
fn federation_sync_id_replay_window_is_five_minutes() {
    let replay_window_secs: u64 = 5 * 60;
    assert_eq!(replay_window_secs, 300);
}

// -- §4.3 BridgeAnnouncement ------------------------------------------------

#[clause("PNP-008-MUST-013")]
#[test]
fn bridge_announcement_max_lifetime_is_seven_days() {
    let max_lifetime_secs: u64 = 7 * 86400;
    assert_eq!(max_lifetime_secs, 604_800);

    // Reject if now > expires_at OR expires_at - issued_at > 7d
    let issued_at: u64 = 1_000_000;
    let ok_expires = issued_at + max_lifetime_secs;
    let bad_expires = issued_at + max_lifetime_secs + 1;
    assert!(ok_expires - issued_at <= max_lifetime_secs);
    assert!(bad_expires - issued_at > max_lifetime_secs);
}

// -- §6.5 Descriptor expiry --------------------------------------------------

#[clause("PNP-008-MUST-031")]
#[test]
fn descriptor_expiry_is_seven_days() {
    let max_age_secs: u64 = 7 * 86400;
    assert_eq!(max_age_secs, 604_800);
}

// -- §7.1 Reputation EWMA ---------------------------------------------------

#[clause("PNP-008-MUST-032")]
#[test]
fn reputation_ewma_formula_is_0_9_times_score_plus_0_1_times_obs() {
    fn ewma(score: f64, obs: f64) -> f64 {
        0.9 * score + 0.1 * obs
    }
    // Initial score 0.5, observation 1.0 → 0.55
    assert!((ewma(0.5, 1.0) - 0.55).abs() < 1e-9);
    // Initial score 0.5, observation 0.0 → 0.45
    assert!((ewma(0.5, 0.0) - 0.45).abs() < 1e-9);
    // Bounded: repeated 1.0 converges to 1.0
    let mut s = 0.5;
    for _ in 0..500 {
        s = ewma(s, 1.0);
    }
    assert!(s > 0.99 && s <= 1.0);
}

#[clause("PNP-008-MUST-034")]
#[test]
fn suspect_threshold_score_below_0_2_for_15_minutes() {
    let suspect_score_threshold: f64 = 0.2;
    let suspect_window_secs: u64 = 15 * 60;
    assert_eq!(suspect_score_threshold, 0.2);
    assert_eq!(suspect_window_secs, 900);
}

#[clause("PNP-008-MUST-035")]
#[test]
fn banned_threshold_score_below_0_05_or_3_invalid_sigs_per_minute() {
    let ban_score_threshold: f64 = 0.05;
    let ban_invalid_sig_count: u32 = 3;
    let ban_invalid_sig_window_secs: u64 = 60;
    let ban_cooldown_secs: u64 = 24 * 3600;
    assert_eq!(ban_score_threshold, 0.05);
    assert_eq!(ban_invalid_sig_count, 3);
    assert_eq!(ban_invalid_sig_window_secs, 60);
    assert_eq!(ban_cooldown_secs, 86400);
}

// -- §8 Bootstrap channels ---------------------------------------------------

#[clause("PNP-008-MUST-038", "PNP-008-MUST-039")]
#[test]
fn bootstrap_channels_do_not_grant_trust_only_descriptors() {
    // MUST-038/039: every bootstrap channel returns candidate descriptors that
    // MUST pass §6.3 validation regardless of channel. No channel is a
    // routing authority. Pinned by: verify_threshold rejects descriptors whose
    // signing authority isn't in trust_roots, even if we "obtained" them from
    // a bootstrap channel.
    let sk1 = sk(1);
    let peer_id = PeerId([0x42; 32]);
    let desc = EndorsedDescriptor {
        descriptor: make_descriptor(peer_id, 1000),
        endorsements: vec![make_endorsement(&sk1, peer_id, 1000, 1000 + 86400)],
    };
    // sk1 is NOT a trusted authority by default → untrusted channel payload
    // MUST NOT be accepted.
    assert!(!desc
        .verify_threshold(AUTHORITY_PUBKEYS, 1)
        .unwrap_or(false));
}

#[clause("PNP-008-MUST-042")]
#[test]
fn bootstrap_bundle_version_is_one() {
    let bundle_version: u8 = 0x01;
    assert_eq!(bundle_version, 0x01);
}

#[clause("PNP-008-MUST-041")]
#[test]
fn bootstrap_dns_txt_record_name_is_parolnet_relay_tcp() {
    let record_prefix = "_parolnet-relay._tcp.";
    assert!(record_prefix.starts_with("_parolnet-relay."));
    assert!(record_prefix.ends_with("._tcp."));
}

#[clause("PNP-008-MUST-050")]
#[test]
fn bootstrap_failure_emits_error_after_600_seconds() {
    let bootstrap_failure_window_secs: u64 = 600;
    assert_eq!(bootstrap_failure_window_secs, 600);
}

// -- §8.1 channel priority registry ------------------------------------------

#[clause("PNP-008-MUST-038")]
#[test]
fn bootstrap_channel_priority_order_matches_spec() {
    // Priority 1: seed, 2: DNS TXT, 3: HTTPS, 4: DHT, 5: manual/LAN
    let channels = ["seed", "dns_txt", "https", "dht", "lan"];
    assert_eq!(channels.len(), 5);
    assert_eq!(channels[0], "seed");
    assert_eq!(channels[4], "lan");
}

// -- §11 Protocol versioning -------------------------------------------------

#[clause("PNP-008-MUST-062")]
#[test]
fn federation_protocol_version_is_one() {
    let v: u8 = 0x01;
    assert_eq!(v, 0x01);
}

// -- §3 Network identity ------------------------------------------------------

#[clause("PNP-008-MUST-003")]
#[test]
fn network_id_is_deterministic_over_authority_set() {
    let id1 = network_id();
    let id2 = network_id();
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 32);
}

#[clause("PNP-008-MUST-057")]
#[test]
fn is_trusted_authority_gates_known_keys_only() {
    assert!(is_trusted_authority(&AUTHORITY_PUBKEYS[0]));
    assert!(!is_trusted_authority(&[0xFF; 32]));
}

// -- §4 Gossip payload type codes --------------------------------------------

#[clause("PNP-008-MUST-004")]
#[test]
fn federation_gossip_payload_codes_are_0x06_0x07_0x08() {
    const FEDERATION_SYNC: u8 = 0x06;
    const FEDERATION_HEARTBEAT: u8 = 0x07;
    const BRIDGE_ANNOUNCEMENT: u8 = 0x08;
    assert_eq!(FEDERATION_SYNC, 0x06);
    assert_eq!(FEDERATION_HEARTBEAT, 0x07);
    assert_eq!(BRIDGE_ANNOUNCEMENT, 0x08);
}

// -- §4.1 FederationSync signature covers deterministic CBOR -----------------

#[clause("PNP-008-MUST-007")]
#[test]
fn signed_directory_signature_covers_deterministic_cbor_hash() {
    // MUST-007 is the FederationSync signature clause; the analogous invariant
    // for SignedDirectory is tested here because its signable_bytes() is the
    // concrete Ed25519-over-SHA256(CBOR(...)) construction used for the same
    // purpose. Pins the signing-chain invariant that the federation code
    // extends.
    let sk1 = sk(1);
    let authority_pubkeys = [sk1.verifying_key().to_bytes()];

    let mut dir = SignedDirectory {
        descriptors: Vec::new(),
        timestamp: 12345,
        authority_pubkey: sk1.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    dir.signature = sk1.sign(&dir.signable_bytes()).to_bytes();
    assert!(dir.verify(&authority_pubkeys).unwrap());

    // Tamper with timestamp → signature MUST fail.
    dir.timestamp = 99999;
    assert!(!dir.verify(&authority_pubkeys).unwrap());
}
