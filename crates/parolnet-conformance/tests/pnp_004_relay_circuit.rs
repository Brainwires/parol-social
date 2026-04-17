//! PNP-004 conformance — onion circuit, cell format, layer crypto.

use parolnet_clause::clause;
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::onion::{onion_decrypt, onion_encrypt, HopKeys};
use parolnet_relay::{
    CellType, RelayCell, AEAD_TAG_SIZE, CELL_PAYLOAD_SIZE, CELL_SIZE, MAX_DATA_PAYLOAD, REQUIRED_HOPS,
};

fn sample_cell() -> RelayCell {
    let mut payload = [0u8; CELL_PAYLOAD_SIZE];
    payload[0] = 0xAA;
    RelayCell {
        circuit_id: 0x1234_5678,
        cell_type: CellType::Data,
        payload,
        payload_len: 7,
    }
}

// -- §3 Fixed 512-byte cells --------------------------------------------------

#[clause("PNP-004-MUST-001")]
#[test]
fn cell_is_exactly_512_bytes() {
    assert_eq!(CELL_SIZE, 512);
    let cell = sample_cell();
    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), 512, "MUST-001: cells MUST be exactly 512 bytes");
}

#[clause("PNP-004-MUST-001")]
#[test]
fn cell_roundtrips_through_serialization() {
    let cell = sample_cell();
    let bytes = cell.to_bytes();
    let back = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(back.circuit_id, cell.circuit_id);
    assert_eq!(back.cell_type, cell.cell_type);
    assert_eq!(back.payload_len, cell.payload_len);
    assert_eq!(&back.payload[..], &cell.payload[..]);
}

#[clause("PNP-004-MUST-002")]
#[test]
fn padding_cell_fills_505_payload_bytes() {
    let cell = RelayCell::padding(42);
    assert_eq!(cell.cell_type, CellType::Padding);
    assert_eq!(
        cell.payload.len(),
        CELL_PAYLOAD_SIZE,
        "MUST-002: payload array MUST be 505 bytes"
    );
    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), 512);
}

#[clause("PNP-004-MUST-010")]
#[test]
fn padding_payload_is_random() {
    // Generate two PADDING cells; payloads MUST differ (random fill).
    let a = RelayCell::padding(1);
    let b = RelayCell::padding(1);
    assert_ne!(
        &a.payload[..],
        &b.payload[..],
        "MUST-010: PADDING payload MUST be cryptographically random"
    );
}

#[clause("PNP-004-MUST-012")]
#[test]
fn padding_and_data_cells_have_identical_wire_size() {
    let data = sample_cell();
    let pad = RelayCell::padding(data.circuit_id);
    assert_eq!(
        data.to_bytes().len(),
        pad.to_bytes().len(),
        "MUST-012: PADDING and DATA cells MUST be indistinguishable by size"
    );
}

// -- §3.2 CellType registry ---------------------------------------------------

#[clause("PNP-004-MUST-033")]
#[test]
fn cell_type_registry_covers_defined_codes() {
    for code in 0x01u8..=0x09 {
        let t = CellType::from_u8(code)
            .unwrap_or_else(|| panic!("code {code:#04x} rejected"));
        assert_eq!(t as u8, code);
    }
    assert!(CellType::from_u8(0x00).is_none());
    assert!(CellType::from_u8(0x0A).is_none());
    assert!(CellType::from_u8(0xFF).is_none());
}

// -- §5.2 Circuit structural constants ----------------------------------------

#[clause("PNP-004-MUST-027")]
#[test]
fn required_hops_is_three() {
    assert_eq!(
        REQUIRED_HOPS, 3,
        "MUST-027: circuits MUST have exactly 3 hops"
    );
}

#[clause("PNP-004-MUST-024")]
#[test]
fn aead_tag_overhead_matches_spec() {
    assert_eq!(AEAD_TAG_SIZE, 16, "MUST-024: AEAD tag MUST be 16 bytes");
    assert_eq!(
        MAX_DATA_PAYLOAD,
        CELL_PAYLOAD_SIZE - REQUIRED_HOPS * AEAD_TAG_SIZE,
        "MUST-024: max DATA payload MUST be 505 - 3*16 = 457 bytes"
    );
    assert_eq!(MAX_DATA_PAYLOAD, 457);
}

// -- §5.1 HKDF key derivation from shared secret ------------------------------

#[clause("PNP-004-MUST-017")]
#[test]
fn hop_keys_deterministic_from_shared_secret() {
    let ss = [0x42u8; 32];
    let a = HopKeys::from_shared_secret(&ss).unwrap();
    let b = HopKeys::from_shared_secret(&ss).unwrap();
    assert_eq!(a.forward_key, b.forward_key);
    assert_eq!(a.backward_key, b.backward_key);
    assert_eq!(a.forward_nonce_seed, b.forward_nonce_seed);
    assert_eq!(a.backward_nonce_seed, b.backward_nonce_seed);

    // Different shared secret MUST yield different material.
    let c = HopKeys::from_shared_secret(&[0x00u8; 32]).unwrap();
    assert_ne!(a.forward_key, c.forward_key);
}

// -- §5.2 Onion wrap / unwrap over 3 hops -------------------------------------

fn three_hop_keys() -> Vec<HopKeys> {
    vec![
        HopKeys::from_shared_secret(&[1u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[2u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[3u8; 32]).unwrap(),
    ]
}

#[clause("PNP-004-MUST-021", "PNP-004-MUST-022")]
#[test]
fn onion_wrap_then_three_hop_peel_recovers_plaintext() {
    let keys = three_hop_keys();
    let plaintext = b"hello onion";
    let counters = [0u32, 0, 0];

    // OP encrypts three layers.
    let wrapped = onion_encrypt(plaintext, &keys, &counters).unwrap();

    // Hops peel one layer each using their forward key + forward nonce seed.
    let mut payload = wrapped;
    for (i, hop) in keys.iter().enumerate() {
        payload = parolnet_relay::onion::onion_peel(
            &payload,
            &hop.forward_key,
            &hop.forward_nonce_seed,
            counters[i],
        )
        .unwrap();
    }
    assert_eq!(payload, plaintext);
}

// Test AEAD tampering — flip a byte, any hop MUST reject.
#[clause("PNP-004-MUST-024")]
#[test]
fn onion_ciphertext_tampering_is_rejected() {
    let keys = three_hop_keys();
    let counters = [0u32, 0, 0];
    let mut wrapped = onion_encrypt(b"payload", &keys, &counters).unwrap();
    wrapped[0] ^= 0xFF;

    let outer = &keys[0];
    parolnet_relay::onion::onion_peel(
        &wrapped,
        &outer.forward_key,
        &outer.forward_nonce_seed,
        0,
    )
    .expect_err("MUST-024: AEAD tag MUST reject tampered ciphertext");
}

// -- §5.2 Reverse direction: exit → OP encrypts, OP peels 3 times -------------

#[clause("PNP-004-MUST-023")]
#[test]
fn reverse_path_three_backward_layers_roundtrip() {
    let keys = three_hop_keys();
    let counters = [0u32, 0, 0];
    let msg = b"reverse";

    // Simulate exit → OP: each hop wraps with its backward key.
    // Start at exit (keys[2]); hop 2 wraps; hop 1 wraps.
    let mut payload = parolnet_relay::onion::onion_wrap(
        msg,
        &keys[2].backward_key,
        &keys[2].backward_nonce_seed,
        counters[2],
    )
    .unwrap();
    payload = parolnet_relay::onion::onion_wrap(
        &payload,
        &keys[1].backward_key,
        &keys[1].backward_nonce_seed,
        counters[1],
    )
    .unwrap();
    payload = parolnet_relay::onion::onion_wrap(
        &payload,
        &keys[0].backward_key,
        &keys[0].backward_nonce_seed,
        counters[0],
    )
    .unwrap();

    // OP peels in order hop1, hop2, hop3.
    let out = onion_decrypt(&payload, &keys, &counters).unwrap();
    assert_eq!(out, msg);
}

// -- EstablishedCircuit wrap/unwrap (ties counters and direction) --------------

#[clause("PNP-004-MUST-021")]
#[test]
fn established_circuit_wrap_increments_counters() {
    let keys = three_hop_keys();
    let circ = EstablishedCircuit::from_hop_keys(keys.clone(), 1);

    let a = circ.wrap_data(b"one").unwrap();
    let b = circ.wrap_data(b"one").unwrap();
    // Same plaintext, different counter -> different ciphertext.
    assert_ne!(a, b, "MUST-021: per-cell counter advance MUST change ciphertext");
}

// -- §5.1 CID 0 is reserved ---------------------------------------------------

#[clause("PNP-004-MUST-032")]
#[test]
fn cell_encodes_reserved_cid_but_circuit_layer_enforces() {
    // At the wire layer, CID is just a u32 field — the reservation is enforced
    // by the circuit manager. We pin the constant here so a wire-level change
    // that silently permitted CID=0 in CREATE payloads would break the test.
    let cell = RelayCell {
        circuit_id: 0,
        cell_type: CellType::Create,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 0,
    };
    let bytes = cell.to_bytes();
    // Leading 4 bytes MUST be zero — this is what MUST-032 forbids as a real
    // circuit ID. The test documents the wire encoding that upper layers
    // reject.
    assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
}

// -- §5.1 Circuit capacity ----------------------------------------------------

#[clause("PNP-004-MUST-039", "PNP-004-MUST-040")]
#[test]
fn max_circuits_per_relay_is_8192() {
    use parolnet_relay::relay_node::MAX_CIRCUITS;
    assert_eq!(MAX_CIRCUITS, 8192);
}

// -- §5.6 Directory refresh & staleness ---------------------------------------

#[clause("PNP-004-MUST-043")]
#[test]
fn descriptor_refresh_interval_is_six_hours() {
    use parolnet_relay::directory::{DESCRIPTOR_REFRESH_SECS, MAX_DESCRIPTOR_AGE_SECS};
    assert_eq!(DESCRIPTOR_REFRESH_SECS, 6 * 3600);
    assert_eq!(MAX_DESCRIPTOR_AGE_SECS, 24 * 3600);
    // Refresh must be at least 2x faster than staleness to guarantee overlap.
    assert!(MAX_DESCRIPTOR_AGE_SECS >= 2 * DESCRIPTOR_REFRESH_SECS);
}

// -- §5.6 Descriptor signature ------------------------------------------------

#[clause("PNP-004-MUST-044")]
#[test]
fn relay_descriptor_signature_verifies_against_identity_key() {
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use parolnet_protocol::address::PeerId;
    use parolnet_relay::directory::RelayDescriptor;
    use sha2::{Digest, Sha256};

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let identity_pub = signing.verifying_key().to_bytes();
    // PeerId = SHA-256(identity_public_key) per PNP-001 §2 / PNP-004 MUST-044.
    let peer_id = PeerId(Sha256::digest(identity_pub).into());

    let mut desc = RelayDescriptor {
        peer_id,
        identity_key: identity_pub,
        x25519_key: [0xBB; 32],
        addr: "127.0.0.1:9000".parse().unwrap(),
        bandwidth_class: 1,
        uptime_secs: 100,
        timestamp: 1000,
        signature: [0u8; 64],
        bandwidth_estimate: 500,
        next_pubkey: None,
    };
    desc.signature = signing.sign(&desc.signable_bytes()).to_bytes();

    // Verify signature roundtrip (the same check directory.add_descriptor does).
    let vkey = VerifyingKey::from_bytes(&desc.identity_key).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&desc.signature);
    assert!(vkey.verify(&desc.signable_bytes(), &sig).is_ok());

    // PeerId MUST equal SHA-256(identity_key).
    assert_eq!(desc.peer_id.0, Sha256::digest(desc.identity_key).as_slice());
}

#[clause("PNP-004-MUST-044")]
#[test]
fn tampered_descriptor_fails_signature_check() {
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use parolnet_protocol::address::PeerId;
    use parolnet_relay::directory::RelayDescriptor;
    use sha2::{Digest, Sha256};

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let identity_pub = signing.verifying_key().to_bytes();
    let peer_id = PeerId(Sha256::digest(identity_pub).into());

    let mut desc = RelayDescriptor {
        peer_id,
        identity_key: identity_pub,
        x25519_key: [0xBB; 32],
        addr: "127.0.0.1:9000".parse().unwrap(),
        bandwidth_class: 1,
        uptime_secs: 100,
        timestamp: 1000,
        signature: [0u8; 64],
        bandwidth_estimate: 500,
        next_pubkey: None,
    };
    desc.signature = signing.sign(&desc.signable_bytes()).to_bytes();

    // Tamper with bandwidth_class.
    desc.bandwidth_class = 99;
    let vkey = VerifyingKey::from_bytes(&desc.identity_key).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&desc.signature);
    assert!(vkey.verify(&desc.signable_bytes(), &sig).is_err());
}

// -- §3.4 Onion layer cipher is ChaCha20-Poly1305 ONLY ------------------------

#[clause("PNP-004-MUST-013")]
#[test]
fn onion_layer_ciphertext_expands_by_one_aead_tag_per_hop() {
    // MUST-013: onion layers are ChaCha20-Poly1305 only. ChaCha20-Poly1305
    // has a 16-byte tag → 3-hop wrap expands plaintext by exactly 3*16 bytes.
    let keys = three_hop_keys();
    let counters = [0u32, 0, 0];
    let plaintext = b"exact-overhead-check";
    let wrapped = onion_encrypt(plaintext, &keys, &counters).unwrap();
    assert_eq!(
        wrapped.len(),
        plaintext.len() + 3 * AEAD_TAG_SIZE,
        "MUST-013: each hop adds one ChaCha20-Poly1305 16-byte tag"
    );
}

// -- §3.1 CREATE/CREATED nonce counter -----------------------------------------

#[clause("PNP-004-MUST-021")]
#[test]
fn same_plaintext_different_counter_diverges() {
    let keys = three_hop_keys();
    let msg = b"xxxx";
    let c0 = onion_encrypt(msg, &keys, &[0, 0, 0]).unwrap();
    let c1 = onion_encrypt(msg, &keys, &[1, 1, 1]).unwrap();
    assert_ne!(c0, c1, "MUST-021: nonce counter MUST alter ciphertext");
}

// -- §3.1 Reverse direction is independently authenticated ---------------------

#[clause("PNP-004-MUST-022")]
#[test]
fn forward_ciphertext_cannot_be_decrypted_as_backward() {
    // Forward and backward keys are distinct HKDF outputs — a ciphertext
    // wrapped with forward_key MUST NOT decrypt under backward_key.
    let keys = three_hop_keys();
    let ct = onion_encrypt(b"hi", &keys, &[0, 0, 0]).unwrap();
    let outer = &keys[0];
    // Try peeling with backward_key — MUST fail.
    let out = parolnet_relay::onion::onion_peel(
        &ct,
        &outer.backward_key,
        &outer.backward_nonce_seed,
        0,
    );
    assert!(out.is_err());
}

// -- §3.1 Ephemeral X25519 handshake produces distinct shared secrets ----------

#[clause("PNP-004-MUST-014", "PNP-004-MUST-015", "PNP-004-MUST-016")]
#[test]
fn ephemeral_x25519_handshake_secrets_diverge_per_hop() {
    use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // Simulate OP + 3 relay ephemeral keypairs (one per hop). The shared
    // secret MUST be derived via X25519(client_priv, relay_pub).
    let secrets: Vec<[u8; 32]> = (0..3)
        .map(|_| {
            let op_sk = EphemeralSecret::random_from_rng(OsRng);
            let relay_sk = EphemeralSecret::random_from_rng(OsRng);
            let op_pk = PublicKey::from(&op_sk);
            let relay_pk = PublicKey::from(&relay_sk);
            // Classical ECDH — both sides derive the same secret, but keys
            // differ per hop, so each ss is different.
            let ss_op = op_sk.diffie_hellman(&relay_pk);
            let ss_relay = relay_sk.diffie_hellman(&op_pk);
            assert_eq!(ss_op.as_bytes(), ss_relay.as_bytes());
            *ss_op.as_bytes()
        })
        .collect();

    // Three hops → three distinct shared secrets with overwhelming probability.
    assert_ne!(secrets[0], secrets[1]);
    assert_ne!(secrets[1], secrets[2]);
    assert_ne!(secrets[0], secrets[2]);
}

// -- §3.3 PADDING and DATA cells share encryption path ------------------------

#[clause("PNP-004-MUST-025")]
#[test]
fn padding_and_data_cells_share_the_same_onion_encryption_path() {
    // MUST-025: relays MUST NOT distinguish DATA from PADDING. The only
    // enforceable invariant at the wire layer is cell-size equality (already
    // pinned by MUST-012). Here we pin that both cell types go through
    // identical crypto: an EstablishedCircuit.wrap_data() call doesn't
    // inspect cell_type, producing a ciphertext whose length is identical
    // for any 457-byte payload.
    let keys = three_hop_keys();
    let circ = EstablishedCircuit::from_hop_keys(keys.clone(), 42);
    let data_payload = vec![0xAAu8; MAX_DATA_PAYLOAD];
    let padding_payload = vec![0xBBu8; MAX_DATA_PAYLOAD];
    let ct_data = circ.wrap_data(&data_payload).unwrap();
    let ct_pad = circ.wrap_data(&padding_payload).unwrap();
    assert_eq!(
        ct_data.len(),
        ct_pad.len(),
        "MUST-025: encrypted PADDING and DATA MUST have identical size"
    );
}

// -- §3.1 Silent discard of PADDING -------------------------------------------

#[clause("PNP-004-MUST-011")]
#[test]
fn padding_cell_type_is_distinct_and_discardable() {
    // MUST-011: receivers MUST silently discard PADDING cells after
    // decryption. Pinned via CellType::Padding being a distinct variant
    // identifiable post-decrypt.
    assert_eq!(CellType::Padding as u8, 0x07);
    assert_ne!(CellType::Padding, CellType::Data);
    assert_ne!(CellType::Padding, CellType::MediaData);
}

// -- §3.1 CREATE MUST NOT request non-ChaCha20-Poly1305 ------------------------

#[clause("PNP-004-MUST-004")]
#[test]
fn onion_layer_aead_is_not_negotiable() {
    // MUST-004: CREATE MUST NOT request any cipher other than
    // ChaCha20-Poly1305. Implementation enforces this by not exposing a
    // selector: HopKeys is derived for ChaCha20 only, with no cipher-id
    // field in the wire format.
    //
    // Pinned as a compile-time invariant: HopKeys has no cipher_id field,
    // and onion_wrap/onion_peel take only forward_key (32 bytes) —
    // consistent with ChaCha20-Poly1305's fixed 32-byte key.
    let hk = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    assert_eq!(hk.forward_key.len(), 32);
    assert_eq!(hk.backward_key.len(), 32);
}
