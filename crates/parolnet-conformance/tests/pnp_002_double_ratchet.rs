//! PNP-002 conformance — receiving Double Ratchet messages (§5.7).
//!
//! PNP-002-MUST-041: a receiver changes no session state for a message that fails
//! authentication. Session state is compared through the persistence export, which holds
//! every field of a session.
//!
//! PNP-002-MUST-042: the complete ratchet header is in the AEAD associated data.

use parolnet_clause::clause;
use parolnet_core::envelope::{
    decrypt_for_peer, encrypt_for_peer, encrypt_into_envelope, try_bootstrap_and_decrypt,
};
use parolnet_core::session::SessionManager;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{RatchetHeader, RatchetSession};
use parolnet_protocol::address::PeerId;
use x25519_dalek::{PublicKey, StaticSecret};

const AAD: &[u8] = b"cleartext header";
const NOW: u64 = 1_700_000_000;

/// Initiator and responder over one shared secret.
fn session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let shared_secret = [0x42u8; 32];
    let bob_ratchet = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_ratchet_pub = *PublicKey::from(&bob_ratchet).as_bytes();
    let alice =
        DoubleRatchetSession::initialize_initiator(shared_secret, &bob_ratchet_pub).unwrap();
    let bob = DoubleRatchetSession::initialize_responder(shared_secret, bob_ratchet).unwrap();
    (alice, bob)
}

/// Messages both ways, a DH ratchet step on each side per round.
fn converse(alice: &mut DoubleRatchetSession, bob: &mut DoubleRatchetSession) {
    for round in 0..3u8 {
        let (h, ct) = alice.encrypt(&[1, round], AAD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), [1, round]);
        let (h, ct) = bob.encrypt(&[2, round], AAD).unwrap();
        assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), [2, round]);
    }
}

/// The message must be refused and the session must be what it was.
fn assert_refused_without_effect(
    session: &mut DoubleRatchetSession,
    header: &RatchetHeader,
    ciphertext: &[u8],
    aad: &[u8],
    what: &str,
) {
    let before = session.export_bytes();
    assert!(
        session.decrypt(header, ciphertext, aad).is_err(),
        "{what}: must not decrypt"
    );
    assert!(
        session.export_bytes() == before,
        "{what}: a message that failed authentication changed session state (PNP-002-MUST-041)"
    );
}

#[clause("PNP-002-MUST-041")]
#[test]
fn message_failing_authentication_changes_no_ratchet_state() {
    let (mut alice, mut bob) = session_pair();
    converse(&mut alice, &mut bob);
    let (header, ct) = alice.encrypt(b"genuine", AAD).unwrap();

    let mut tampered = ct.clone();
    tampered[0] ^= 0x01;
    assert_refused_without_effect(&mut bob, &header, &tampered, AAD, "tampered ciphertext");
    assert_refused_without_effect(&mut bob, &header, &ct, b"other", "other associated data");

    // A header announcing a new ratchet key asks for a DH ratchet step.
    let mut new_key = header.clone();
    new_key.ratchet_key = [0x77; 32];
    assert_refused_without_effect(&mut bob, &new_key, &ct, AAD, "unknown ratchet key");
    new_key.previous_chain_length = 400;
    assert_refused_without_effect(&mut bob, &new_key, &ct, AAD, "unknown key, long chain");

    // Message numbers ahead of the chain ask for skipped keys: inside the limit and past it.
    for ahead in [
        1,
        300,
        300,
        300,
        300,
        5_000,
        u32::MAX - header.message_number,
    ] {
        let mut skipping = header.clone();
        skipping.message_number += ahead;
        assert_refused_without_effect(&mut bob, &skipping, &ct, AAD, "message number ahead");
    }

    // The genuine message still decrypts, and so does everything after it.
    assert_eq!(bob.decrypt(&header, &ct, AAD).unwrap(), b"genuine");
    assert_refused_without_effect(&mut bob, &header, &ct, AAD, "replay");
    converse(&mut alice, &mut bob);
}

#[clause("PNP-002-MUST-041")]
#[test]
fn skipped_key_is_deleted_only_by_a_message_that_authenticates() {
    let (mut alice, mut bob) = session_pair();
    converse(&mut alice, &mut bob);
    let (h1, ct1) = alice.encrypt(b"one", AAD).unwrap();
    let (h2, ct2) = alice.encrypt(b"two", AAD).unwrap();
    // The second arrives first: the key of the first waits as a skipped key.
    assert_eq!(bob.decrypt(&h2, &ct2, AAD).unwrap(), b"two");

    let mut tampered = ct1.clone();
    *tampered.last_mut().unwrap() ^= 0x80;
    assert_refused_without_effect(&mut bob, &h1, &tampered, AAD, "tampered late message");
    assert_refused_without_effect(&mut bob, &h1, &[], AAD, "empty late message");

    assert_eq!(bob.decrypt(&h1, &ct1, AAD).unwrap(), b"one");
    assert_refused_without_effect(&mut bob, &h1, &ct1, AAD, "replayed late message");
    converse(&mut alice, &mut bob);
}

#[clause("PNP-002-MUST-041")]
#[test]
fn envelope_of_another_session_leaves_every_session_as_it_was() {
    let me = PeerId([0xEE; 32]);
    let sessions = SessionManager::new();
    let mut peers = Vec::new();
    for n in 1..=3u8 {
        let (theirs, ours) = session_pair();
        sessions.add_session(PeerId([n; 32]), ours);
        peers.push((PeerId([n; 32]), theirs));
    }
    let export = |sessions: &SessionManager| {
        let mut all = sessions.export_all();
        all.sort();
        all
    };

    // A third identity's envelope, tried against each of our sessions.
    let (mut stranger, _) = session_pair();
    let before = export(&sessions);
    let foreign = encrypt_into_envelope(&mut stranger, &me, 0x01, b"?", NOW, None).unwrap();
    for (peer, _) in &peers {
        assert!(decrypt_for_peer(&sessions, peer, &foreign).is_err());
    }
    assert!(export(&sessions) == before);

    for (peer, theirs) in &mut peers {
        let env = encrypt_into_envelope(theirs, &me, 0x01, b"hello", NOW, None).unwrap();
        assert_eq!(
            decrypt_for_peer(&sessions, peer, &env).unwrap().plaintext,
            b"hello"
        );
        let reply = encrypt_for_peer(&sessions, peer, 0x01, b"hi", NOW, None).unwrap();
        let decoded = parolnet_core::envelope::decrypt_from_envelope(theirs, &reply).unwrap();
        assert_eq!(decoded.plaintext, b"hi");
    }
}

#[clause("PNP-002-MUST-041")]
#[test]
fn first_message_failing_authentication_replaces_no_session() {
    let our_ik = [0x0A; 32];
    let scanner_ik = [0x0B; 32];
    let scanner = PeerId::from_public_key(&scanner_ik);
    let me = PeerId::from_public_key(&our_ik);

    // A session we already hold with that identity.
    let sessions = SessionManager::new();
    let (mut theirs, ours) = session_pair();
    sessions.add_session(scanner, ours);
    let before = sessions.export_all();

    // A first message naming that identity, made without our pairing seed.
    let qr = parolnet_core::bootstrap::generate_qr_payload_with_ratchet(&our_ik, None).unwrap();
    let ratchet_pub = *PublicKey::from(&StaticSecret::from(qr.ratchet_secret)).as_bytes();
    let mut forger = DoubleRatchetSession::initialize_initiator([0x66; 32], &ratchet_pub).unwrap();
    let forged = encrypt_into_envelope(
        &mut forger,
        &me,
        0x01,
        b"forged",
        NOW,
        Some(PeerId(scanner_ik)),
    )
    .unwrap();
    assert!(
        try_bootstrap_and_decrypt(&sessions, &forged, &our_ik, &qr.seed, &qr.ratchet_secret)
            .is_err()
    );
    assert!(sessions.export_all() == before);

    let env = encrypt_into_envelope(&mut theirs, &me, 0x01, b"still here", NOW, None).unwrap();
    assert_eq!(
        decrypt_for_peer(&sessions, &scanner, &env)
            .unwrap()
            .plaintext,
        b"still here"
    );
}

// -- §5.7 rule 2 — the whole ratchet header is authenticated ------------------

#[clause("PNP-002-MUST-042")]
#[test]
fn ratchet_header_altered_in_transit_fails_authentication() {
    let (mut alice, mut bob) = session_pair();
    converse(&mut alice, &mut bob);

    // Alice's previous chain: three messages, of which Bob gets the first only for now.
    let (h, ct) = alice.encrypt(b"a0", AAD).unwrap();
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"a0");
    let (h_skipped, ct_skipped) = alice.encrypt(b"a1", AAD).unwrap();
    let (h_late, ct_late) = alice.encrypt(b"a2", AAD).unwrap();
    // A message from Bob moves Alice to a new sending chain.
    let (h, ct) = bob.encrypt(b"b", AAD).unwrap();
    assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), b"b");
    let (header, ct) = alice.encrypt(b"first of the new chain", AAD).unwrap();
    assert_ne!(header.ratchet_key, h_late.ratchet_key);
    assert_eq!(header.previous_chain_length, 3);

    // previous_chain_length raised (keys for messages never sent) and lowered (the previous
    // chain closed before its late messages).
    for pn in [4, 500, 1000, u32::MAX, 2, 1, 0] {
        let mut altered = header.clone();
        altered.previous_chain_length = pn;
        assert_refused_without_effect(&mut bob, &altered, &ct, AAD, "previous_chain_length");
    }
    for n in [1, 2, 999, u32::MAX] {
        let mut altered = header.clone();
        altered.message_number = n;
        assert_refused_without_effect(&mut bob, &altered, &ct, AAD, "message_number");
    }
    for byte in [0, 8, 31] {
        let mut altered = header.clone();
        altered.ratchet_key[byte] ^= 0x01;
        assert_refused_without_effect(&mut bob, &altered, &ct, AAD, "ratchet_key");
    }

    // The genuine message decrypts afterwards, and the previous chain's late messages too:
    // the first through the chain's skipped keys, with its own header checked the same way.
    assert_eq!(
        bob.decrypt(&header, &ct, AAD).unwrap(),
        b"first of the new chain"
    );
    let mut altered = h_skipped.clone();
    altered.previous_chain_length += 1;
    assert_refused_without_effect(
        &mut bob,
        &altered,
        &ct_skipped,
        AAD,
        "previous_chain_length of a skipped message",
    );
    assert_eq!(bob.decrypt(&h_skipped, &ct_skipped, AAD).unwrap(), b"a1");
    assert_eq!(bob.decrypt(&h_late, &ct_late, AAD).unwrap(), b"a2");
    converse(&mut alice, &mut bob);
}
