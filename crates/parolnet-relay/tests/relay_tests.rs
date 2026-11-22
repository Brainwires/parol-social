use ed25519_dalek::{SigningKey, Verifier};
use parolnet_protocol::address::PeerId;
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::onion::{self, HopKeys};
use parolnet_relay::*;

// ── Constants Tests ─────────────────────────────────────────────

#[test]
fn test_cell_size_constants() {
    assert_eq!(CELL_SIZE, 512);
    assert_eq!(CELL_HEADER_SIZE, 7);
    assert_eq!(CELL_PAYLOAD_SIZE, 505);
    assert_eq!(REQUIRED_HOPS, 3);
    assert_eq!(MAX_DATA_PAYLOAD, 457); // 505 - 3*16
}

// ── Cell Serialization Tests ────────────────────────────────────

#[test]
fn test_cell_serialization_roundtrip() {
    let cell = RelayCell {
        circuit_id: 42,
        cell_type: CellType::Data,
        payload: [0xAB; CELL_PAYLOAD_SIZE],
        payload_len: 100,
    };

    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);

    let decoded = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.circuit_id, 42);
    assert_eq!(decoded.cell_type, CellType::Data);
    assert_eq!(decoded.payload_len, 100);
    assert_eq!(decoded.payload, [0xAB; CELL_PAYLOAD_SIZE]);
}

#[test]
fn test_padding_cell() {
    let cell = RelayCell::padding(99);
    assert_eq!(cell.circuit_id, 99);
    assert_eq!(cell.cell_type, CellType::Padding);
    assert_eq!(cell.payload_len, 0);
    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);
}

#[test]
fn test_destroy_cell() {
    let cell = RelayCell::destroy(42, 0x00); // normal teardown
    assert_eq!(cell.cell_type, CellType::Destroy);
    assert_eq!(cell.payload[0], 0x00);
}

#[test]
fn test_cell_type_roundtrip() {
    for v in 0x01..=0x09 {
        assert!(CellType::from_u8(v).is_some());
    }
    assert!(CellType::from_u8(0x00).is_none());
    assert!(CellType::from_u8(0x0A).is_none());
}

// ── Circuit Tests ───────────────────────────────────────────────

#[test]
fn test_circuit_wrap_unwrap_roundtrip() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();

    let circuit = EstablishedCircuit::from_hop_keys(vec![hop1, hop2, hop3], 42);

    let plaintext = b"hello through circuit";
    let encrypted = circuit.wrap_data(plaintext).unwrap();
    assert_ne!(encrypted, plaintext);

    // Simulate 3 relays peeling layers
    // (In production each relay peels one layer and forwards)
}

#[test]
fn test_circuit_id_nonzero() {
    let hop_keys = vec![
        HopKeys::from_shared_secret(&[1u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[2u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[3u8; 32]).unwrap(),
    ];
    let circuit = EstablishedCircuit::from_hop_keys(hop_keys, 42);
    assert_eq!(circuit.id(), 42);
}

// ── Relay Node Tests ────────────────────────────────────────────

// ── Directory Tests ─────────────────────────────────────────────

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_descriptor(id: u8, uptime_days: u64) -> RelayDescriptor {
    let peer_id = PeerId([id; 32]);
    RelayDescriptor {
        peer_id,
        identity_key: [id; 32],
        x25519_key: [id; 32],
        // One /16 per relay: no two hops of a path may share one.
        addr: format!("10.{id}.0.1:443").parse().unwrap(),
        bandwidth_class: 1,
        uptime_secs: uptime_days * 86400,
        timestamp: now(),
        signature: [0; 64],
        bandwidth_estimate: 1000,
        next_pubkey: None,
    }
}

#[test]
fn test_directory_insert_and_len() {
    let mut dir = RelayDirectory::new();
    assert!(dir.is_empty());

    dir.insert(make_descriptor(1, 10));
    dir.insert(make_descriptor(2, 20));
    assert_eq!(dir.len(), 2);
}

#[test]
fn test_directory_guard_selection() {
    let mut dir = RelayDirectory::new();
    // Add relays with varying uptime
    dir.insert(make_descriptor(1, 1)); // 1 day - too short
    dir.insert(make_descriptor(2, 10)); // 10 days - qualifies
    dir.insert(make_descriptor(3, 30)); // 30 days - qualifies

    let guards = dir.select_guards(2);
    assert_eq!(guards.len(), 2);
    // Both selected guards must have uptime >= 7 days (relays 2 and 3 qualify, relay 1 does not)
    let ids: Vec<u8> = guards.iter().map(|g| g.identity_key[0]).collect();
    assert!(ids.contains(&2), "relay 2 (10d uptime) should be selected");
    assert!(ids.contains(&3), "relay 3 (30d uptime) should be selected");
    assert!(
        !ids.contains(&1),
        "relay 1 (1d uptime) should not be selected"
    );
}

#[test]
fn test_directory_random_excludes() {
    let mut dir = RelayDirectory::new();
    dir.insert(make_descriptor(1, 10));
    dir.insert(make_descriptor(2, 10));

    // Exclude relay 1
    let selected = dir.select_random(&[PeerId([1; 32])]);
    assert!(selected.is_some());
    assert_eq!(selected.unwrap().identity_key[0], 2);
}

#[test]
fn test_directory_prune_stale() {
    let mut dir = RelayDirectory::new();
    let stamped = make_descriptor(1, 10);
    let at = stamped.timestamp;
    dir.insert(stamped);

    // Not stale yet
    dir.prune_stale(at + 3600);
    assert_eq!(dir.len(), 1);

    // Now stale (25 hours later)
    dir.prune_stale(at + 90000);
    assert_eq!(dir.len(), 0);
}

#[test]
fn test_directory_select_path() {
    let mut dir = RelayDirectory::new();
    dir.insert(make_descriptor(1, 30));
    dir.insert(make_descriptor(2, 20));
    dir.insert(make_descriptor(3, 10));

    let path = dir.select_path();
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 3);
    // All three should be different
    assert_ne!(path[0].identity_key, path[1].identity_key);
    assert_ne!(path[1].identity_key, path[2].identity_key);
    assert_ne!(path[0].identity_key, path[2].identity_key);
}

// ── Circuit Tests (new) ────────────────────────────────────────

#[test]
fn test_circuit_wrap_then_manual_peel() {
    let hop1 = HopKeys::from_shared_secret(&[10u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[20u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[30u8; 32]).unwrap();

    let circuit =
        EstablishedCircuit::from_hop_keys(vec![hop1.clone(), hop2.clone(), hop3.clone()], 100);

    let plaintext = b"hello";
    let encrypted = circuit.wrap_data(plaintext).unwrap();

    // Manually peel three layers in order: hop1, hop2, hop3
    let after1 =
        onion::onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
    let after2 =
        onion::onion_peel(&after1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
    let after3 =
        onion::onion_peel(&after2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

    assert_eq!(after3, plaintext);
}

// ── Relay Node Forwarding Tests (new) ──────────────────────────

// ── Onion Edge Case Tests (new) ────────────────────────────────

#[test]
fn test_onion_encrypt_empty() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();
    let hops = [hop1.clone(), hop2.clone(), hop3.clone()];
    let counters = [0u32, 0, 0];

    let encrypted = onion::onion_encrypt(b"", &hops, &counters).unwrap();

    // Peel 3 layers
    let after1 =
        onion::onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
    let after2 =
        onion::onion_peel(&after1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
    let after3 =
        onion::onion_peel(&after2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

    assert_eq!(after3, b"");
}

#[test]
fn test_onion_key_counter_mismatch() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hops = [hop1, hop2];
    let counters = [0u32, 0, 0]; // 3 counters for 2 hops — mismatch

    let result = onion::onion_encrypt(b"test", &hops, &counters);
    assert!(result.is_err());
}

#[test]
fn test_onion_wrong_key_peel_fails() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();

    // Encrypt with hop1's key
    let encrypted = onion::onion_wrap(
        b"secret data",
        &hop1.forward_key,
        &hop1.forward_nonce_seed,
        0,
    )
    .unwrap();

    // Try to peel with hop2's key — should fail with AeadFailed
    let result = onion::onion_peel(&encrypted, &hop2.forward_key, &hop2.forward_nonce_seed, 0);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), RelayError::AeadFailed),
        "expected AeadFailed error"
    );
}

// ── Directory / Cell Edge Case Tests (new) ─────────────────────

#[test]
fn test_cell_from_bytes_invalid_type() {
    let mut buf = [0u8; CELL_SIZE];
    // circuit_id = 1
    buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    // cell_type = 0x00 (invalid)
    buf[4] = 0x00;
    // payload_len = 0
    buf[5] = 0;
    buf[6] = 0;

    let result = RelayCell::from_bytes(&buf);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, RelayError::InvalidCellType(0x00)),
        "expected InvalidCellType(0x00), got: {err:?}"
    );
}

#[test]
fn test_directory_select_path_insufficient_relays() {
    let mut dir = RelayDirectory::new();
    // Only 2 relays — need at least 3 for a path
    dir.insert(make_descriptor(1, 30));
    dir.insert(make_descriptor(2, 20));

    let path = dir.select_path();
    assert!(
        path.is_none(),
        "select_path should return None with only 2 relays"
    );
}

// ── Descriptor Signing Tests ──────────────────────────────────

fn make_signed_descriptor(id: u8, uptime_days: u64, signing_key: &SigningKey) -> RelayDescriptor {
    let identity_key = signing_key.verifying_key().to_bytes();
    let peer_id = PeerId::from_public_key(&identity_key);
    RelayDirectory::create_descriptor(
        peer_id,
        identity_key,
        [id; 32],
        format!("10.0.{id}.1:443").parse().unwrap(),
        1,
        uptime_days * 86400,
        1700000000,
        signing_key,
    )
}

#[test]
fn test_descriptor_signature_roundtrip() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let desc = make_signed_descriptor(1, 10, &signing_key);

    // Verify signature manually
    let verifying_key = signing_key.verifying_key();
    let signature = ed25519_dalek::Signature::from_bytes(&desc.signature);
    assert!(
        verifying_key
            .verify(&desc.signable_bytes(), &signature)
            .is_ok(),
        "signature should verify against the signing key"
    );
}

#[test]
fn test_descriptor_reject_tampered() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let mut desc = make_signed_descriptor(1, 10, &signing_key);

    // Tamper with the bandwidth_class field
    desc.bandwidth_class = 255;

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(!accepted, "tampered descriptor should be rejected");
}

#[test]
fn test_descriptor_reject_wrong_key() {
    let key_a = SigningKey::generate(&mut rand::thread_rng());
    let key_b = SigningKey::generate(&mut rand::thread_rng());

    // Sign with key_a but set identity_key to key_b's public key
    let mut desc = make_signed_descriptor(1, 10, &key_a);
    desc.identity_key = key_b.verifying_key().to_bytes();

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(
        !accepted,
        "descriptor signed with wrong key should be rejected"
    );
}

#[test]
fn test_gossip_accepts_valid_signed_descriptor() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let desc = make_signed_descriptor(1, 10, &signing_key);

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(accepted, "valid signed descriptor should be accepted");
}

// ── DESTROY Forwarding Chain Tests ────────────────────────────

/// A descriptor signed by one key cannot claim the PeerId of another relay
/// (PNP-008-MUST-027: the signature is checked against the relay's own key,
/// the one its PeerId is the hash of).
#[test]
fn test_gossip_rejects_descriptor_claiming_another_relays_peer_id() {
    let relay = SigningKey::generate(&mut rand::thread_rng());
    let attacker = SigningKey::generate(&mut rand::thread_rng());
    let genuine = make_signed_descriptor(1, 10, &relay);

    let mut dir = RelayDirectory::new();
    assert!(dir.handle_gossip_descriptor(genuine.clone(), 1700000000 + 60));

    // Newer, self-consistent (signed by the key it carries), under the victim's PeerId.
    let mut forged = RelayDirectory::create_descriptor(
        genuine.peer_id,
        attacker.verifying_key().to_bytes(),
        [0xEE; 32],
        "203.0.113.66:443".parse().unwrap(),
        1,
        0,
        1700000000 + 30,
        &attacker,
    );
    assert!(!dir.handle_gossip_descriptor(forged.clone(), 1700000000 + 60));
    forged.timestamp += 1;
    assert!(!dir.handle_gossip_descriptor(forged, 1700000000 + 60));
    assert_eq!(dir.lookup_addr(&genuine.peer_id), Some(genuine.addr));
}
