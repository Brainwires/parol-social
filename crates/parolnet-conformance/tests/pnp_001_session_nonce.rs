//! PNP-001 §3.3 / §9 `N-SESSION`: the nonce of the session AEAD.
//!
//! The nonce is not on the wire and the message key never leaves a session, except in one
//! place: a receiver that gets message 1 before message 0 stores the key of message 0, and
//! the persistence export holds stored keys. With that key the test opens message 0 itself,
//! using the AEAD primitive directly, with the nonce and associated data built from the
//! spec text. That it opens pins the construction; that it does not open under any other
//! construction pins that this is the only one.

use parolnet_clause::clause;
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{Aead, RatchetHeader, RatchetSession};
use x25519_dalek::{PublicKey, StaticSecret};

const UPPER_AD: &[u8] = b"cbor(cleartext header)";

fn session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let bob_ratchet = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub = *PublicKey::from(&bob_ratchet).as_bytes();
    let alice = DoubleRatchetSession::initialize_initiator([0x42; 32], &bob_pub).unwrap();
    let bob = DoubleRatchetSession::initialize_responder([0x42; 32], bob_ratchet).unwrap();
    (alice, bob)
}

/// The stored skipped keys of an export: `(ratchet_key, message_number, message_key)`, the
/// 68-byte records that end it.
fn skipped_keys(export: &[u8], count: usize) -> Vec<([u8; 32], u32, [u8; 32])> {
    let tail = &export[export.len() - 68 * count..];
    assert_eq!(
        u32::from_be_bytes(
            export[export.len() - 68 * count - 4..][..4]
                .try_into()
                .unwrap()
        ),
        count as u32,
        "the export holds {count} skipped key(s)"
    );
    tail.chunks(68)
        .map(|r| {
            (
                r[..32].try_into().unwrap(),
                u32::from_be_bytes(r[32..36].try_into().unwrap()),
                r[36..].try_into().unwrap(),
            )
        })
        .collect()
}

/// `ratchet_public_key[0..8] || msg_number (4 bytes, big-endian)`.
fn n_session(header: &RatchetHeader) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&header.ratchet_key[..8]);
    nonce[8..].copy_from_slice(&header.message_number.to_be_bytes());
    nonce
}

/// PNP-001-MUST-007 / PNP-002-MUST-042: the 40-byte header, then the upper layer's data.
fn associated_data(header: &RatchetHeader) -> Vec<u8> {
    let mut ad = header.ratchet_key.to_vec();
    ad.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    ad.extend_from_slice(&header.message_number.to_be_bytes());
    ad.extend_from_slice(UPPER_AD);
    ad
}

#[clause("PNP-001-MUST-006", "PNP-001-MUST-047")]
#[test]
fn session_nonce_is_ratchet_key_prefix_and_message_number() {
    let (mut alice, mut bob) = session_pair();
    // Move both sides past their first chains so the counters are not all zero: Alice's
    // header then carries a non-zero previous chain length.
    for i in 0..3u8 {
        let (h, ct) = alice.encrypt(&[i], UPPER_AD).unwrap();
        bob.decrypt(&h, &ct, UPPER_AD).unwrap();
    }
    let (h, ct) = bob.encrypt(b"reply", UPPER_AD).unwrap();
    alice.decrypt(&h, &ct, UPPER_AD).unwrap();

    // Seven messages of Alice's new chain; Bob receives only the last.
    let sent: Vec<(RatchetHeader, Vec<u8>)> = (0..7u8)
        .map(|i| alice.encrypt(&[0xA0, i], UPPER_AD).unwrap())
        .collect();
    let (last_header, last_ct) = &sent[6];
    assert_eq!(last_header.previous_chain_length, 3);
    assert_eq!(
        bob.decrypt(last_header, last_ct, UPPER_AD).unwrap(),
        [0xA0, 6]
    );

    let stored = skipped_keys(&bob.export_bytes(), 6);
    for (i, (header, ciphertext)) in sent[..6].iter().enumerate() {
        let (ratchet_key, number, key) = stored[i];
        assert_eq!(ratchet_key, header.ratchet_key);
        assert_eq!(number, header.message_number);
        assert_eq!(number, i as u32);

        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ad = associated_data(header);
        let nonce = n_session(header);
        assert_eq!(
            cipher.decrypt(&nonce, ciphertext, &ad).unwrap(),
            [0xA0, i as u8],
            "message {i} opens under N-SESSION"
        );

        // No other construction opens it: the one PNP-001 described before v0.16
        // (`chain_index (4) || seq_number (8)`), the fields the other way round, another
        // part of the ratchet key, a little-endian counter, or an all-zero nonce.
        let mut old = [0u8; 12];
        old[4..].copy_from_slice(&u64::from(number).to_be_bytes());
        let mut swapped = [0u8; 12];
        swapped[..4].copy_from_slice(&number.to_be_bytes());
        swapped[4..].copy_from_slice(&header.ratchet_key[..8]);
        let mut other_part = nonce;
        other_part[..8].copy_from_slice(&header.ratchet_key[8..16]);
        let mut little = nonce;
        little[8..].copy_from_slice(&(number + 1).to_le_bytes());
        for (what, wrong) in [
            ("chain || seq", old),
            ("number first", swapped),
            ("key bytes 8..16", other_part),
            ("little-endian", little),
            ("zero", [0u8; 12]),
        ] {
            if wrong == nonce {
                continue;
            }
            assert!(
                cipher.decrypt(&wrong, ciphertext, &ad).is_err(),
                "message {i} opened under the nonce `{what}`"
            );
        }
    }
}

// MUST-041: no (key, nonce) pair repeats. Every message has its own key, within a chain the
// nonces differ as well, and a new chain changes the key part of the nonce.
#[clause("PNP-001-MUST-041")]
#[test]
fn no_key_nonce_pair_repeats_across_chains() {
    let (mut alice, mut bob) = session_pair();
    let mut keys = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    for round in 0..4u8 {
        // Bob skips five of Alice's messages each round, which stores their keys.
        let sent: Vec<_> = (0..6u8)
            .map(|i| alice.encrypt(&[round, i], UPPER_AD).unwrap())
            .collect();
        bob.decrypt(&sent[5].0, &sent[5].1, UPPER_AD).unwrap();
        for (h, _) in &sent {
            assert!(nonces.insert(n_session(h)), "a nonce repeated");
        }
        let (h, ct) = bob.encrypt(b"turn", UPPER_AD).unwrap();
        alice.decrypt(&h, &ct, UPPER_AD).unwrap();
    }
    for (_, _, key) in skipped_keys(&bob.export_bytes(), 20) {
        assert!(keys.insert(key), "a message key repeated");
    }
}
