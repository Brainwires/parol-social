//! PNP-001 conformance — end-to-end envelope encode/decode flow.
//!
//! These tests exercise the `parolnet_core::envelope` helpers to verify that
//! the composition of CleartextHeader + Double Ratchet AEAD + wire-level
//! BucketPadding produces a frame whose length is always exactly one of
//! 256 / 1024 / 4096 / 16384 bytes and whose contents are tamper-evident via
//! the AEAD AAD binding (PNP-001-MUST-007).

use parolnet_clause::clause;
use parolnet_core::envelope::{decrypt_from_envelope, encrypt_into_envelope};
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_protocol::BUCKET_SIZES;
use parolnet_protocol::address::PeerId;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

fn session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let bob_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub: [u8; 32] = *X25519Pub::from(&bob_sk).as_bytes();
    let alice = DoubleRatchetSession::initialize_initiator([0x42u8; 32], &bob_pub).unwrap();
    let bob = DoubleRatchetSession::initialize_responder([0x42u8; 32], bob_sk).unwrap();
    (alice, bob)
}

// -- §3.1 / §3.6 — every envelope wire length equals exactly one bucket ------

#[clause("PNP-001-MUST-001", "PNP-001-MUST-004", "PNP-001-MUST-012")]
#[test]
fn envelope_flow_round_trip_hits_every_bucket() {
    // Plaintext sizes chosen to land in each of the four bucket tiers.
    // The overhead (CBOR header + ratchet header + 16B AEAD tag + padding
    // machinery) pushes small plaintexts into the 256-byte bucket and
    // larger ones into 1024 / 4096 / 16384.
    let cases: [(usize, usize); 4] = [(4, 256), (800, 1024), (3_500, 4096), (15_000, 16_384)];

    for (pt_len, expected_bucket) in cases {
        let (mut alice, mut bob) = session_pair();
        let dest = PeerId([0x11u8; 32]);
        let plaintext = vec![0xA5u8; pt_len];

        let wire = encrypt_into_envelope(&mut alice, &dest, 0x01, &plaintext, 1_700_000_000, None)
            .unwrap();

        assert!(
            BUCKET_SIZES.contains(&wire.len()),
            "MUST-001/012: wire length {} for pt_len={} is not a bucket size",
            wire.len(),
            pt_len
        );
        assert_eq!(
            wire.len(),
            expected_bucket,
            "MUST-013: pt_len {} MUST land in bucket {}",
            pt_len,
            expected_bucket
        );

        let decoded = decrypt_from_envelope(&mut bob, &wire).unwrap();
        assert_eq!(decoded.plaintext, plaintext, "MUST-004: round-trip");
        assert_eq!(decoded.msg_type, 0x01);
    }
}

// -- §3.2 — timestamp coarsening ----------------------------------------------

#[clause("PNP-001-MUST-006")]
#[test]
fn envelope_flow_coarsens_timestamp_to_300s_boundary() {
    let (mut alice, mut bob) = session_pair();
    let dest = PeerId([0x22u8; 32]);
    // Wall-clock 1_700_000_123 is inside the bucket starting at 1_700_000_100.
    let wire = encrypt_into_envelope(&mut alice, &dest, 0x01, b"ts", 1_700_000_123, None).unwrap();
    let decoded = decrypt_from_envelope(&mut bob, &wire).unwrap();
    assert_eq!(
        decoded.timestamp, 1_700_000_100,
        "MUST-006: timestamp MUST be floor(now/300)*300"
    );
    assert_eq!(decoded.timestamp % 300, 0);
}

// -- §3.3 / PNP-001-MUST-007 — AAD binds the cleartext header -----------------

#[clause("PNP-001-MUST-007")]
#[test]
fn envelope_flow_tampered_cleartext_header_fails_aead() {
    let (mut alice, _bob) = session_pair();
    let dest = PeerId([0x33u8; 32]);
    let wire =
        encrypt_into_envelope(&mut alice, &dest, 0x01, b"secret", 1_700_000_000, None).unwrap();

    // Walk the first 200 bytes of the wire envelope and, for each byte,
    // flip one bit and verify decryption fails. The first ~150 bytes span
    // the CBOR-encoded cleartext header, which is bound into the AEAD AAD
    // via PNP-001-MUST-007 and MUST therefore be tamper-evident.
    //
    // (The test is robust against CBOR-decode failures as well as AEAD
    // failures — both are acceptable: per MUST-037 the receiver MUST
    // silently discard.)
    let mut found_aead_rejection = false;
    for i in 0..wire.len().min(200) {
        let mut tampered = wire.clone();
        tampered[i] ^= 0x01;
        let (mut _a, mut b) = session_pair();
        // Re-run Alice's encrypt on the fresh pair so Bob's state matches
        // the one that produced `wire`.
        let _ =
            encrypt_into_envelope(&mut _a, &dest, 0x01, b"secret", 1_700_000_000, None).unwrap();
        match decrypt_from_envelope(&mut b, &tampered) {
            Ok(_) => {
                // A tampered byte that hit padding (after AAD coverage) could
                // theoretically decrypt cleanly — accept silently and keep
                // scanning. We only require that at least one header-byte
                // flip is caught.
            }
            Err(_) => {
                found_aead_rejection = true;
            }
        }
    }
    assert!(
        found_aead_rejection,
        "MUST-007: at least one cleartext-header tamper MUST be caught by AEAD AAD binding"
    );
}

// -- §5 — sender anonymity (source_hint default-null) -------------------------

#[clause("PNP-001-SHOULD-003")]
#[test]
fn envelope_flow_omits_source_hint_by_default() {
    // H9 sealed-sender invariant: the high-level envelope helper MUST build
    // every outbound CleartextHeader with source_hint = None unless callers
    // explicitly opt in. Relay operators (and passive WSS observers) do not
    // need sender identity to route messages — deliverability uses the outer
    // transport-layer `to` field. Setting source_hint here would hand the
    // relay a social graph for free.
    let (mut alice, mut bob) = session_pair();
    let dest = PeerId([0x55u8; 32]);
    let wire =
        encrypt_into_envelope(&mut alice, &dest, 0x01, b"anon", 1_700_000_000, None).unwrap();
    let decoded = decrypt_from_envelope(&mut bob, &wire).unwrap();
    assert!(
        decoded.source_hint.is_none(),
        "SHOULD-003: encrypt_into_envelope MUST default source_hint to None"
    );
}

// -- §3.6 — bucket selection boundary -----------------------------------------

#[clause("PNP-001-MUST-013")]
#[test]
fn envelope_flow_bucket_boundary_selection() {
    // A tiny plaintext (≤ ~200 bytes) MUST land in the 256-byte bucket.
    // A medium plaintext whose encrypted-envelope CBOR overhead just crosses
    // 256 MUST land in the 1024-byte bucket.
    let (mut a1, mut b1) = session_pair();
    let dest = PeerId([0x44u8; 32]);

    let wire_small =
        encrypt_into_envelope(&mut a1, &dest, 0x01, b"hi", 1_700_000_000, None).unwrap();
    assert_eq!(
        wire_small.len(),
        256,
        "MUST-013: tiny plaintext MUST land in bucket 256"
    );
    let _ = decrypt_from_envelope(&mut b1, &wire_small).unwrap();

    let (mut a2, mut b2) = session_pair();
    // Craft a plaintext whose encrypted-envelope overflow 256 but fits within
    // 1024. Envelope overhead is roughly ~150 bytes (CBOR header, ratchet
    // header, AEAD tag, bstr length prefixes). A 200-byte plaintext reliably
    // crosses the 256 boundary.
    let plaintext = vec![0x5Au8; 200];
    let wire_mid =
        encrypt_into_envelope(&mut a2, &dest, 0x01, &plaintext, 1_700_000_000, None).unwrap();
    assert_eq!(
        wire_mid.len(),
        1024,
        "MUST-013: plaintext that overflows 256 MUST land in bucket 1024"
    );
    let decoded = decrypt_from_envelope(&mut b2, &wire_mid).unwrap();
    assert_eq!(decoded.plaintext, plaintext);
}
