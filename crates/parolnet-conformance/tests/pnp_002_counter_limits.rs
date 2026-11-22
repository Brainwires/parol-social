//! PNP-002 conformance — counter limits of a Double Ratchet session (§5.9).
//!
//! PNP-002-MUST-045: a sender stops at `MAX_CHAIN_LENGTH` messages in a chain, with an error
//! of its own, and sends again on the chain the next DH ratchet step gives it.
//! PNP-002-MUST-046: a receiver rejects a `message_number` or `previous_chain_length` past
//! the limit before anything else, with no change to the session.
//! PNP-002-MUST-047: no counter wraps, and saved state with a counter past its limit is
//! refused.
//! PNP-002-MUST-048: a send that fails changes no session state.
//!
//! The limit is 2^24 messages. A session is put next to it through its persistence format
//! (`export_bytes` / `import_bytes`), with the counters of both ends moved by the same
//! amount: the chain keys stay in step, so the messages still decrypt. Session state is
//! compared through the same export, which holds every field of a session.

use parolnet_clause::clause;
use parolnet_core::CoreError;
use parolnet_core::envelope::encrypt_for_peer;
use parolnet_core::session::SessionManager;
use parolnet_crypto::double_ratchet::{DoubleRatchetSession, MAX_CHAIN_LENGTH};
use parolnet_crypto::{CryptoError, RatchetHeader, RatchetSession};
use parolnet_protocol::address::PeerId;
use x25519_dalek::{PublicKey, StaticSecret};

const AAD: &[u8] = b"cleartext header";

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

/// A pair that has talked in both directions: both hold every chain.
fn established_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let (mut alice, mut bob) = session_pair();
    for round in 0..2u8 {
        let (h, ct) = alice.encrypt(&[1, round], AAD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), [1, round]);
        let (h, ct) = bob.encrypt(&[2, round], AAD).unwrap();
        assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), [2, round]);
    }
    (alice, bob)
}

// ── The persistence format (`DoubleRatchetSession::export_bytes`) ────────────────────
//
// version(1) || root_key(32) || four optional 32-byte fields, each behind a flag byte
// || send_n(4) || recv_n(4) || previous_send_n(4) || skipped_count(4)
// || [ratchet_key(32) || message_number(4) || message_key(32)]...

const SEND_N: usize = 0;
const RECV_N: usize = 1;
const PREVIOUS_SEND_N: usize = 2;

/// Offset of the three counters in an exported session.
fn counters_at(exported: &[u8]) -> usize {
    let mut pos = 1 + 32;
    for _ in 0..4 {
        pos += if exported[pos] != 0 { 33 } else { 1 };
    }
    pos
}

fn read_counter(session: &DoubleRatchetSession, which: usize) -> u32 {
    let bytes = session.export_bytes();
    let at = counters_at(&bytes) + which * 4;
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// The exported session with one counter replaced.
fn exported_with(session: &DoubleRatchetSession, which: usize, value: u32) -> Vec<u8> {
    let mut bytes = session.export_bytes();
    let at = counters_at(&bytes) + which * 4;
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn with_counter(session: &DoubleRatchetSession, which: usize, value: u32) -> DoubleRatchetSession {
    DoubleRatchetSession::import_bytes(&exported_with(session, which, value))
        .expect("a counter within its limit is restored")
}

/// A pair whose Alice-to-Bob chain has `left` message numbers left before the limit.
fn pair_before_the_limit(left: u32) -> (DoubleRatchetSession, DoubleRatchetSession) {
    let (mut alice, mut bob) = established_pair();
    // One message on Alice's current sending chain, so that Bob holds its receiving side
    // and both chain keys have taken the same number of steps.
    let (h, ct) = alice.encrypt(b"opens the chain", AAD).unwrap();
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"opens the chain");
    let sent = read_counter(&alice, SEND_N);
    assert_eq!(read_counter(&bob, RECV_N), sent);

    let alice = with_counter(&alice, SEND_N, MAX_CHAIN_LENGTH - left);
    let bob = with_counter(&bob, RECV_N, MAX_CHAIN_LENGTH - left);
    (alice, bob)
}

#[clause("PNP-002-MUST-045")]
#[test]
fn sender_stops_at_the_chain_limit_and_resumes_on_a_new_chain() {
    assert_eq!(MAX_CHAIN_LENGTH, 1 << 24, "§5.9: MAX_CHAIN_LENGTH = 2^24");
    let (mut alice, mut bob) = pair_before_the_limit(2);

    // The last two message numbers of the chain.
    let (h1, ct1) = alice.encrypt(b"next to last", AAD).unwrap();
    assert_eq!(h1.message_number, MAX_CHAIN_LENGTH - 2);
    let (h2, ct2) = alice.encrypt(b"last", AAD).unwrap();
    assert_eq!(h2.message_number, MAX_CHAIN_LENGTH - 1);
    assert_eq!(read_counter(&alice, SEND_N), MAX_CHAIN_LENGTH);

    // At the limit: an error of its own, every time, and nothing is encrypted.
    for _ in 0..3 {
        match alice.encrypt(b"one too many", AAD) {
            Err(CryptoError::SendChainExhausted { limit }) => assert_eq!(limit, MAX_CHAIN_LENGTH),
            other => panic!("MUST-045: expected SendChainExhausted, got {other:?}"),
        }
    }
    assert_eq!(read_counter(&alice, SEND_N), MAX_CHAIN_LENGTH);

    // The receiver takes the chain to its end.
    assert_eq!(bob.decrypt(&h1, &ct1, AAD).unwrap(), b"next to last");
    assert_eq!(bob.decrypt(&h2, &ct2, AAD).unwrap(), b"last");
    assert_eq!(read_counter(&bob, RECV_N), MAX_CHAIN_LENGTH);

    // A message from the peer carries a new ratchet key: the DH ratchet step gives Alice a
    // new sending chain, numbered from 0, and the full length of the old one goes out as
    // `previous_chain_length`.
    let (h, ct) = bob.encrypt(b"reply", AAD).unwrap();
    assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), b"reply");
    let (h, ct) = alice.encrypt(b"new chain", AAD).unwrap();
    assert_eq!(h.message_number, 0);
    assert_eq!(h.previous_chain_length, MAX_CHAIN_LENGTH);
    assert_ne!(h.ratchet_key, h2.ratchet_key);
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"new chain");
}

#[clause("PNP-002-MUST-045")]
#[test]
fn the_envelope_layer_reports_an_exhausted_chain_as_such() {
    let (alice, _bob) = pair_before_the_limit(0);
    let peer = PeerId([0x22; 32]);
    let sessions = SessionManager::new();
    sessions.add_session(peer, alice);

    let err = encrypt_for_peer(&sessions, &peer, 0x01, b"text", 1_700_000_000, None)
        .expect_err("MUST-045: no envelope is produced at the limit");
    assert!(
        matches!(
            err,
            CoreError::Crypto(CryptoError::SendChainExhausted { .. })
        ),
        "the layer above is told which error it is, got {err:?}"
    );
    // Still there, still at the limit: the session is closed by the layer above, or
    // resumes when the peer's next ratchet key arrives.
    assert!(sessions.has_session(&peer));
}

/// The message must be refused with a counter-limit error and the session must be what it
/// was.
fn assert_out_of_range(
    session: &mut DoubleRatchetSession,
    header: &RatchetHeader,
    ciphertext: &[u8],
    what: &str,
) {
    let before = session.export_bytes();
    match session.decrypt(header, ciphertext, AAD) {
        Err(CryptoError::CounterOutOfRange { .. }) => {}
        other => panic!("MUST-046: {what}: expected CounterOutOfRange, got {other:?}"),
    }
    assert!(
        session.export_bytes() == before,
        "MUST-046: {what}: the session changed"
    );
}

#[clause("PNP-002-MUST-046")]
#[test]
fn receiver_rejects_counters_past_the_limit() {
    let (mut alice, mut bob) = established_pair();
    let (genuine, ct) = alice.encrypt(b"genuine", AAD).unwrap();

    for n in [
        MAX_CHAIN_LENGTH,
        MAX_CHAIN_LENGTH + 1,
        u32::MAX - 1,
        u32::MAX,
    ] {
        let mut forged = genuine.clone();
        forged.message_number = n;
        assert_out_of_range(&mut bob, &forged, &ct, "message_number");
        // On a ratchet key the receiver has not seen: no DH ratchet step is taken for it.
        forged.ratchet_key = [0x5A; 32];
        assert_out_of_range(&mut bob, &forged, &ct, "message_number, new ratchet key");
    }
    for pn in [MAX_CHAIN_LENGTH + 1, u32::MAX] {
        let mut forged = genuine.clone();
        forged.previous_chain_length = pn;
        assert_out_of_range(&mut bob, &forged, &ct, "previous_chain_length");
        forged.ratchet_key = [0x5A; 32];
        assert_out_of_range(
            &mut bob,
            &forged,
            &ct,
            "previous_chain_length, new ratchet key",
        );
    }

    // The genuine message is unaffected.
    assert_eq!(bob.decrypt(&genuine, &ct, AAD).unwrap(), b"genuine");
}

#[clause("PNP-002-MUST-046")]
#[test]
fn receiver_rejects_the_message_past_the_end_of_a_full_chain() {
    // Bob has received the whole chain. A header that names the message after the last one,
    // on the same ratchet key, is refused for its number alone.
    let (mut alice, mut bob) = pair_before_the_limit(1);
    let (last, ct) = alice.encrypt(b"last", AAD).unwrap();
    assert_eq!(bob.decrypt(&last, &ct, AAD).unwrap(), b"last");

    let mut beyond = last.clone();
    beyond.message_number = MAX_CHAIN_LENGTH;
    assert_out_of_range(&mut bob, &beyond, &ct, "the number after the last");
    assert_eq!(read_counter(&bob, RECV_N), MAX_CHAIN_LENGTH);

    // `previous_chain_length` equal to the limit is the length of a chain used to its end,
    // and is accepted (the first test sends it); one more is not.
    let mut forged = last.clone();
    forged.previous_chain_length = MAX_CHAIN_LENGTH + 1;
    assert_out_of_range(
        &mut bob,
        &forged,
        &ct,
        "previous_chain_length past a full chain",
    );
}

#[clause("PNP-002-MUST-047")]
#[test]
fn saved_state_with_a_counter_past_its_limit_is_refused() {
    let (alice, _bob) = established_pair();

    for which in [SEND_N, RECV_N, PREVIOUS_SEND_N] {
        // At the limit: a chain used to its end. Restored.
        let at_limit = exported_with(&alice, which, MAX_CHAIN_LENGTH);
        assert!(DoubleRatchetSession::import_bytes(&at_limit).is_ok());
        // Past it: refused whole.
        for value in [MAX_CHAIN_LENGTH + 1, u32::MAX - 1, u32::MAX] {
            let bad = exported_with(&alice, which, value);
            match DoubleRatchetSession::import_bytes(&bad) {
                Err(CryptoError::CounterOutOfRange { .. }) => {}
                Err(other) => panic!("MUST-047: expected CounterOutOfRange, got {other:?}"),
                Ok(_) => panic!("MUST-047: counter {which} = {value} was restored"),
            }
        }
    }
}

#[clause("PNP-002-MUST-047")]
#[test]
fn saved_state_with_a_skipped_key_past_the_limit_is_refused() {
    // Bob receives the second of two messages first: he stores one skipped key.
    let (mut alice, mut bob) = established_pair();
    let (_h1, _ct1) = alice.encrypt(b"late", AAD).unwrap();
    let (h2, ct2) = alice.encrypt(b"early", AAD).unwrap();
    assert_eq!(bob.decrypt(&h2, &ct2, AAD).unwrap(), b"early");

    let exported = bob.export_bytes();
    let count_at = counters_at(&exported) + 12;
    assert_eq!(
        u32::from_be_bytes(exported[count_at..count_at + 4].try_into().unwrap()),
        1
    );
    let number_at = count_at + 4 + 32;
    assert!(DoubleRatchetSession::import_bytes(&exported).is_ok());

    for value in [MAX_CHAIN_LENGTH, u32::MAX] {
        let mut bad = exported.clone();
        bad[number_at..number_at + 4].copy_from_slice(&value.to_be_bytes());
        assert!(
            matches!(
                DoubleRatchetSession::import_bytes(&bad),
                Err(CryptoError::CounterOutOfRange { .. })
            ),
            "MUST-047: a skipped key numbered {value} was restored"
        );
    }
    let mut edge = exported.clone();
    edge[number_at..number_at + 4].copy_from_slice(&(MAX_CHAIN_LENGTH - 1).to_be_bytes());
    assert!(DoubleRatchetSession::import_bytes(&edge).is_ok());
}

#[clause("PNP-002-MUST-047")]
#[test]
fn counters_stop_at_the_limit_and_never_wrap() {
    // Every counter of both ends, driven to the end of a chain and across the DH ratchet
    // step that follows, stays within [0, MAX_CHAIN_LENGTH]. A wrapped counter would read 0
    // (or the session would have panicked on the overflow).
    let (mut alice, mut bob) = pair_before_the_limit(1);
    let (h, ct) = alice.encrypt(b"last", AAD).unwrap();
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"last");
    assert_eq!(read_counter(&alice, SEND_N), MAX_CHAIN_LENGTH);
    assert_eq!(read_counter(&bob, RECV_N), MAX_CHAIN_LENGTH);

    assert!(alice.encrypt(b"refused", AAD).is_err());
    assert_eq!(read_counter(&alice, SEND_N), MAX_CHAIN_LENGTH);

    let (h, ct) = bob.encrypt(b"reply", AAD).unwrap();
    assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), b"reply");
    assert_eq!(read_counter(&alice, SEND_N), 0);
    assert_eq!(read_counter(&alice, PREVIOUS_SEND_N), MAX_CHAIN_LENGTH);

    // The state at the limit survives a save and restore as it is.
    let restored = DoubleRatchetSession::import_bytes(&alice.export_bytes()).unwrap();
    assert_eq!(read_counter(&restored, PREVIOUS_SEND_N), MAX_CHAIN_LENGTH);
}

#[clause("PNP-002-MUST-048")]
#[test]
fn a_send_refused_at_the_limit_changes_nothing() {
    let (mut alice, mut bob) = pair_before_the_limit(1);
    let (last, last_ct) = alice.encrypt(b"last", AAD).unwrap();

    let before = alice.export_bytes();
    for plaintext in [&b"a"[..], &[0u8; 4096][..], &[][..]] {
        assert!(alice.encrypt(plaintext, AAD).is_err());
        assert!(
            alice.export_bytes() == before,
            "MUST-048: a refused send changed the session"
        );
    }

    // In particular the sending chain key did not move: after the failures the session
    // still receives, and the chain it gets from the next DH ratchet step is the one the
    // peer derives.
    assert_eq!(bob.decrypt(&last, &last_ct, AAD).unwrap(), b"last");
    let (h, ct) = bob.encrypt(b"reply", AAD).unwrap();
    assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), b"reply");
    let (h, ct) = alice.encrypt(b"after", AAD).unwrap();
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"after");
}

#[clause("PNP-002-MUST-048")]
#[test]
fn a_send_that_fails_for_another_reason_changes_nothing() {
    // A responder that has received nothing has no sending chain yet.
    let (mut alice, mut bob) = session_pair();
    let before = bob.export_bytes();
    assert!(bob.encrypt(b"too early", AAD).is_err());
    assert!(
        bob.export_bytes() == before,
        "MUST-048: a failed send changed the session"
    );

    // The session is as good as new.
    let (h, ct) = alice.encrypt(b"first", AAD).unwrap();
    assert_eq!(bob.decrypt(&h, &ct, AAD).unwrap(), b"first");
    let (h, ct) = bob.encrypt(b"second", AAD).unwrap();
    assert_eq!(h.message_number, 0);
    assert_eq!(alice.decrypt(&h, &ct, AAD).unwrap(), b"second");
}

#[clause("PNP-002-MUST-048")]
#[test]
fn chain_key_and_message_number_advance_together() {
    // Sends interleaved with refused sends on the way to the limit: every message that was
    // produced decrypts under the number it carries.
    let (mut alice, mut bob) = pair_before_the_limit(3);
    let mut sent = Vec::new();
    loop {
        match alice.encrypt(b"m", AAD) {
            Ok(message) => sent.push(message),
            Err(CryptoError::SendChainExhausted { .. }) => break,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(sent.len(), 3);
    let numbers: Vec<u32> = sent.iter().map(|(h, _)| h.message_number).collect();
    assert_eq!(
        numbers,
        [
            MAX_CHAIN_LENGTH - 3,
            MAX_CHAIN_LENGTH - 2,
            MAX_CHAIN_LENGTH - 1
        ]
    );
    // Out of order, across the last numbers of the chain.
    for (h, ct) in sent.iter().rev() {
        assert_eq!(bob.decrypt(h, ct, AAD).unwrap(), b"m");
    }
}

// -- Test vector: specs/vectors/PNP-002/counter_limits.json ---------------------

fn vector_u32s(v: &serde_json::Value, key: &str) -> Vec<u32> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("vector field {key}"))
        .iter()
        .map(|n| u32::try_from(n.as_u64().unwrap()).unwrap())
        .collect()
}

#[clause("PNP-002-MUST-045", "PNP-002-MUST-046", "PNP-002-MUST-047")]
#[test]
fn counter_limits_match_the_published_vector() {
    let v: serde_json::Value =
        parolnet_conformance::vectors::load("PNP-002", "counter_limits.json");
    assert_eq!(
        v["max_chain_length"].as_u64().unwrap(),
        u64::from(MAX_CHAIN_LENGTH)
    );

    let (mut alice, mut bob) = established_pair();
    let (genuine, ct) = alice.encrypt(b"genuine", AAD).unwrap();
    let past_the_limit = |session: &mut DoubleRatchetSession, header: &RatchetHeader| {
        matches!(
            session.decrypt(header, &ct, AAD),
            Err(CryptoError::CounterOutOfRange { .. })
        )
    };

    // A forged header never decrypts; what the vector fixes is which ones are refused for
    // their counters alone.
    for n in vector_u32s(&v, "rejected_message_numbers") {
        let mut header = genuine.clone();
        header.message_number = n;
        assert!(past_the_limit(&mut bob, &header), "message_number {n}");
    }
    for n in vector_u32s(&v, "accepted_message_numbers") {
        let mut header = genuine.clone();
        header.message_number = n;
        assert!(!past_the_limit(&mut bob, &header), "message_number {n}");
    }
    for pn in vector_u32s(&v, "rejected_previous_chain_lengths") {
        let mut header = genuine.clone();
        header.previous_chain_length = pn;
        assert!(
            past_the_limit(&mut bob, &header),
            "previous_chain_length {pn}"
        );
    }
    for pn in vector_u32s(&v, "accepted_previous_chain_lengths") {
        let mut header = genuine.clone();
        header.previous_chain_length = pn;
        // On a ratchet key of its own, so that the header is not the genuine one.
        header.ratchet_key = [0x6B; 32];
        assert!(
            !past_the_limit(&mut bob, &header),
            "previous_chain_length {pn}"
        );
    }

    for which in [SEND_N, RECV_N, PREVIOUS_SEND_N] {
        for value in vector_u32s(&v, "accepted_stored_counters") {
            assert!(
                DoubleRatchetSession::import_bytes(&exported_with(&alice, which, value)).is_ok(),
                "stored counter {which} = {value}"
            );
        }
        for value in vector_u32s(&v, "rejected_stored_counters") {
            assert!(
                DoubleRatchetSession::import_bytes(&exported_with(&alice, which, value)).is_err(),
                "stored counter {which} = {value}"
            );
        }
    }
}
