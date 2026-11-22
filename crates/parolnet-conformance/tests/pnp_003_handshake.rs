//! PNP-003 conformance: the BootstrapHandshake, SAS verification and the hand-over to
//! PNP-002 (§3.3, §3.4, §4, §5.4, §5.5), against `parolnet_core::bootstrap::pairing`: the
//! state machine both ends of every pairing run (the native client drives it in
//! `parolnet-app`; `pnp_003_pairing.rs` tests it there, end to end).

use hmac::{Hmac, KeyInit, Mac};
use parolnet_clause::clause;
use parolnet_core::bootstrap::pairing::{
    BOOTSTRAP_INIT, BOOTSTRAP_RESP, BootstrapHandshake, BootstrapKey, HANDSHAKE_INIT,
    HANDSHAKE_RESPONSE, HANDSHAKE_TIMEOUT_MS, Pairing, PairingError, PairingOutput, PairingState,
    SAS_CONFIRM, SAS_TIMEOUT_MS, SECRET_SHARED_TIMEOUT_MS, SasVerify, message_type, sas_mac,
};
use parolnet_core::bootstrap::{
    self, NONCE_WINDOW_SECS, NonceTracker, SAS_EMOJI, compute_bootstrap_proof, compute_sas,
    sas_digits, sas_emoji, sas_material,
};
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{IdentityKeyPair, RatchetSession as _};
use sha2::Sha256;

const NOW: u64 = 1_800_000_000_000;
const SEED: [u8; 32] = [0x5E; 32];

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    ciborium::from_reader(bytes).unwrap()
}

fn to_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// The messages of one kind among a step's outputs.
fn sends(outputs: &[PairingOutput]) -> Vec<Vec<u8>> {
    outputs
        .iter()
        .filter_map(|o| match o {
            PairingOutput::Send(m) => Some(m.clone()),
            _ => None,
        })
        .collect()
}

fn session(outputs: Vec<PairingOutput>) -> Option<DoubleRatchetSession> {
    outputs.into_iter().find_map(|o| match o {
        PairingOutput::Session(s) => Some(*s),
        _ => None,
    })
}

fn established(outputs: &[PairingOutput]) -> Option<bool> {
    outputs.iter().find_map(|o| match o {
        PairingOutput::Established { sas_verified } => Some(*sas_verified),
        _ => None,
    })
}

/// Two peers after the QR scan: Alice showed the code (she holds `SEED`), Bob scanned it.
struct Pair {
    alice: IdentityKeyPair,
    bob: IdentityKeyPair,
    bs: [u8; 32],
    nonces_a: NonceTracker,
    nonces_b: NonceTracker,
}

impl Pair {
    fn new() -> Pair {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let bs = bootstrap::derive_bootstrap_secret(
            &SEED,
            &alice.public_key_bytes(),
            &bob.public_key_bytes(),
        )
        .unwrap();
        Pair {
            alice,
            bob,
            bs,
            nonces_a: NonceTracker::default(),
            nonces_b: NonceTracker::default(),
        }
    }

    fn initiate(&self, request_sas: bool) -> (Pairing, Vec<u8>) {
        let mut bs = self.bs;
        let out = Pairing::initiate(
            &self.bob,
            &mut bs,
            self.alice.public_key_bytes(),
            request_sas,
            NOW,
        )
        .unwrap();
        assert_eq!(bs, [0u8; 32], "the caller's copy of BS is erased");
        out
    }

    fn respond(
        &mut self,
        init: &[u8],
        request_sas: bool,
    ) -> Result<(Pairing, Vec<PairingOutput>), PairingError> {
        Pairing::respond(
            &self.alice,
            &BootstrapKey::Seed(&SEED),
            init,
            Some(&self.bob.public_key_bytes()),
            &mut self.nonces_a,
            request_sas,
            NOW,
        )
    }

    /// Both peers AUTHENTICATED: Bob has processed Alice's BOOTSTRAP_RESP. Returns the
    /// pairings and what Bob's processing produced.
    fn authenticated(
        &mut self,
        bob_requests: bool,
        alice_requests: bool,
    ) -> (Pairing, Pairing, Vec<PairingOutput>, Vec<PairingOutput>) {
        let (mut bob, init) = self.initiate(bob_requests);
        let (alice, alice_out) = self.respond(&init, alice_requests).unwrap();
        let resp = sends(&alice_out).remove(0);
        let bob_out = bob.on_message(&resp, &mut self.nonces_b, NOW).unwrap();
        (alice, bob, alice_out, bob_out)
    }
}

// -- §5.4 step 1 -------------------------------------------------------------------

#[clause("PNP-003-MUST-020")]
#[test]
fn the_scanner_starts_with_a_bootstrap_handshake() {
    let pair = Pair::new();
    let (pairing, init) = pair.initiate(false);
    assert_eq!(pairing.state(), PairingState::SecretShared);
    assert_eq!(message_type(&init), Some(BOOTSTRAP_INIT));
    assert_eq!(BOOTSTRAP_INIT, 0x10);
    // The CBOR map of §3.3, field by field.
    let value: ciborium::Value = from_cbor(&init);
    let map = value.as_map().unwrap();
    let get = |name: &str| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("type").unwrap().as_integer(), Some(0x10.into()));
    assert_eq!(
        get("ik").unwrap().as_bytes().unwrap(),
        &pair.bob.public_key_bytes().to_vec()
    );
    assert_eq!(get("ek").unwrap().as_bytes().unwrap().len(), 32);
    assert_eq!(get("proof").unwrap().as_bytes().unwrap().len(), 32);
    assert_eq!(get("nonce").unwrap().as_bytes().unwrap().len(), 16);
    assert!(get("prekey_bundle").unwrap().is_map());
}

// -- §5.4 step 2 -------------------------------------------------------------------

#[clause("PNP-003-MUST-021")]
#[test]
fn the_proof_is_hmac_sha256_of_ik_ek_nonce_under_bs() {
    // Known answer, computed independently (Python hmac): BS from the PNP-003-MUST-012
    // vector, ik = (10 .. 1f) x 2, ek = e2 x 32, nonce = 10 .. 1f.
    let bs: [u8; 32] =
        hex::decode("71109e3bddb3be261768a8e18dd94d1c1ed740ec48406e614b18566b476eb2d6")
            .unwrap()
            .try_into()
            .unwrap();
    let ik: [u8; 32] = std::array::from_fn(|i| 0x10 + (i % 16) as u8);
    let nonce: [u8; 16] = std::array::from_fn(|i| 0x10 + i as u8);
    assert_eq!(
        hex::encode(compute_bootstrap_proof(&bs, &ik, &[0xE2; 32], &nonce).unwrap()),
        "236a0c31eb220e5145f764125374c44b15f483b8501903531480076a223a50cd"
    );

    // And that is what both messages of a real exchange carry, over their own fields.
    let mut pair = Pair::new();
    let (_bob, init) = pair.initiate(false);
    let (_alice, out) = pair.respond(&init, false).unwrap();
    let resp = sends(&out).remove(0);
    for (bytes, sender) in [(&init, &pair.bob), (&resp, &pair.alice)] {
        let msg: BootstrapHandshake = from_cbor(bytes);
        assert_eq!(msg.ik, sender.public_key_bytes());
        assert_eq!(
            msg.proof,
            hmac_sha256(&pair.bs, &[&msg.ik, &msg.ek, &msg.nonce])
        );
    }
    assert_eq!(message_type(&resp), Some(BOOTSTRAP_RESP));
}

// -- §5.4 step 3 -------------------------------------------------------------------

#[clause("PNP-003-MUST-022")]
#[test]
fn a_proof_that_does_not_verify_aborts_the_bootstrap_and_erases_bs() {
    let mut pair = Pair::new();
    let (_bob, init) = pair.initiate(false);

    // The receiver of BOOTSTRAP_INIT: any change to ik-bound fields, or a proof made
    // without the secret, and nothing comes of it.
    let mut wrong_proof: BootstrapHandshake = from_cbor(&init);
    wrong_proof.proof[0] ^= 1;
    let mut wrong_nonce: BootstrapHandshake = from_cbor(&init);
    wrong_nonce.nonce[0] ^= 1;
    let mut wrong_ek: BootstrapHandshake = from_cbor(&init);
    wrong_ek.ek[31] ^= 1;
    let mut forged: BootstrapHandshake = from_cbor(&init);
    forged.proof = hmac_sha256(&[0u8; 32], &[&forged.ik, &forged.ek, &forged.nonce]).to_vec();
    for bad in [wrong_proof, wrong_nonce, wrong_ek, forged] {
        match pair.respond(&to_cbor(&bad), false) {
            Err(PairingError::ProofFailed) => {}
            other => panic!("expected ProofFailed, got {:?}", other.err()),
        }
    }
    // A code made for another seed fails the same way.
    let other_seed = [0x77; 32];
    let refused = Pairing::respond(
        &pair.alice,
        &BootstrapKey::Seed(&other_seed),
        &init,
        None,
        &mut pair.nonces_a,
        false,
        NOW,
    );
    assert!(matches!(refused, Err(PairingError::ProofFailed)));
    // None of that used up the genuine message's nonce: it still verifies.
    let (_alice, out) = pair.respond(&init, false).unwrap();
    let resp = sends(&out).remove(0);

    // The receiver of BOOTSTRAP_RESP: a bad proof aborts its pairing and erases BS.
    let mut tampered: BootstrapHandshake = from_cbor(&resp);
    tampered.proof[5] ^= 0x80;
    let (mut bob, _init) = pair.initiate(false);
    assert!(bob.holds_bootstrap_secret());
    assert_eq!(
        bob.on_message(&to_cbor(&tampered), &mut pair.nonces_b, NOW)
            .err(),
        Some(PairingError::ProofFailed)
    );
    assert_eq!(bob.state(), PairingState::Aborted);
    assert!(!bob.holds_bootstrap_secret(), "BS must be erased on abort");
    assert_eq!(bob.bs_hint(), None);
    // Aborted is final: the genuine answer is not accepted afterwards.
    assert!(
        bob.on_message(&resp, &mut pair.nonces_b, NOW)
            .unwrap()
            .is_empty()
    );
    assert_eq!(bob.state(), PairingState::Aborted);
    // A response from another identity than the one whose code was scanned.
    let mut imposter: BootstrapHandshake = from_cbor(&resp);
    imposter.ik = vec![0x99; 32];
    let (mut bob, _init) = pair.initiate(false);
    assert!(
        bob.on_message(&to_cbor(&imposter), &mut pair.nonces_b, NOW)
            .is_err()
    );
    assert!(!bob.holds_bootstrap_secret());
}

// -- §5.4 step 4 -------------------------------------------------------------------

/// The whole exchange with no SAS: returns each side's PNP-002 session and pairing.
fn establish(pair: &mut Pair) -> (Pairing, Pairing, DoubleRatchetSession, DoubleRatchetSession) {
    let (mut alice, mut bob, _alice_out, bob_out) = pair.authenticated(false, false);
    // No SAS requested: Bob is in the PNP-002 handshake at once and sends its HandshakeInit.
    assert_eq!(bob.state(), PairingState::Handshaking);
    assert_eq!(alice.state(), PairingState::Handshaking);
    let handshake_init = sends(&bob_out).remove(0);
    assert_eq!(message_type(&handshake_init), Some(HANDSHAKE_INIT));
    let alice_out = alice
        .on_message(&handshake_init, &mut pair.nonces_a, NOW)
        .unwrap();
    let handshake_response = sends(&alice_out).remove(0);
    assert_eq!(message_type(&handshake_response), Some(HANDSHAKE_RESPONSE));
    assert_eq!(alice.state(), PairingState::Accepted);
    let alice_session = session(alice_out).expect("Alice's PNP-002 session");
    let bob_out = bob
        .on_message(&handshake_response, &mut pair.nonces_b, NOW)
        .unwrap();
    assert_eq!(established(&bob_out), Some(false));
    assert_eq!(bob.state(), PairingState::Established);
    let bob_session = session(bob_out).expect("Bob's PNP-002 session");
    (alice, bob, alice_session, bob_session)
}

#[clause("PNP-003-MUST-023")]
#[test]
fn prekey_bundles_are_exchanged_and_the_pnp002_handshake_follows() {
    use ed25519_dalek::Verifier as _;
    let mut pair = Pair::new();
    let (_bob, init) = pair.initiate(false);
    let (_alice, out) = pair.respond(&init, false).unwrap();
    let resp = sends(&out).remove(0);

    // Both BootstrapHandshakes carry the sender's PreKeyBundle (PNP-002 §3.1): its identity
    // key, and a signed pre-key whose signature over (spk || spk_id) verifies under it.
    for (bytes, sender) in [(&init, &pair.bob), (&resp, &pair.alice)] {
        let msg: BootstrapHandshake = from_cbor(bytes);
        let bundle = &msg.prekey_bundle;
        assert_eq!(bundle.ik, sender.public_key_bytes());
        assert_eq!(bundle.spk.len(), 32);
        let mut signed = bundle.spk.clone();
        signed.extend_from_slice(&bundle.spk_id.to_be_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&bundle.spk_sig).unwrap();
        sender.verifying_key().verify(&signed, &sig).unwrap();
        assert!(bundle.opks.iter().all(|o| o.key.len() == 32));
    }

    // A bundle the sender's identity key did not sign is refused, valid proof or not.
    let mut bad: BootstrapHandshake = from_cbor(&init);
    bad.prekey_bundle.spk[0] ^= 1;
    let (_b, fresh_init) = pair.initiate(false);
    let mut bad_fresh: BootstrapHandshake = from_cbor(&fresh_init);
    bad_fresh.prekey_bundle.spk = bad.prekey_bundle.spk;
    assert_eq!(
        pair.respond(&to_cbor(&bad_fresh), false).err(),
        Some(PairingError::BadPreKeyBundle)
    );

    // After the proofs, the PNP-002 handshake runs on those bundles and yields the session:
    // a Double Ratchet keyed by X3DH, not by the Bootstrap Secret.
    let mut pair = Pair::new();
    let (mut alice, _bob, mut alice_session, mut bob_session) = establish(&mut pair);
    let (header, ciphertext) = bob_session.encrypt(b"first message", b"aad").unwrap();
    assert_eq!(
        alice_session.decrypt(&header, &ciphertext, b"aad").unwrap(),
        b"first message"
    );
    let (header, ciphertext) = alice_session.encrypt(b"and back", b"").unwrap();
    assert_eq!(
        bob_session.decrypt(&header, &ciphertext, b"").unwrap(),
        b"and back"
    );
    // A session keyed by BS (what the bootstrap session of PNP-001 §5.3.1 is) cannot read it.
    let (header, ciphertext) = bob_session.encrypt(b"x", b"").unwrap();
    let mut bs_keyed = DoubleRatchetSession::initialize_responder(
        pair.bs,
        x25519_dalek::StaticSecret::from([7u8; 32]),
    )
    .unwrap();
    assert!(bs_keyed.decrypt(&header, &ciphertext, b"").is_err());
    // Alice reaches ESTABLISHED with the session's first message.
    assert_eq!(established(&alice.on_first_message()), Some(false));
    assert_eq!(alice.state(), PairingState::Established);
}

// -- §5.4 step 5, §6.5, §7.4 ----------------------------------------------------------

#[clause("PNP-003-MUST-024", "PNP-003-MUST-044", "PNP-003-MUST-050")]
#[test]
fn the_bootstrap_secret_is_erased_once_the_pnp002_session_is_established() {
    let mut pair = Pair::new();
    let (mut alice, mut bob, _alice_out, bob_out) = pair.authenticated(false, false);
    // Held as long as the bootstrap is under way ...
    assert!(alice.holds_bootstrap_secret() && bob.holds_bootstrap_secret());
    assert!(bob.bs_hint().is_some());
    let handshake_init = sends(&bob_out).remove(0);
    let alice_out = alice
        .on_message(&handshake_init, &mut pair.nonces_a, NOW)
        .unwrap();
    assert!(
        alice.holds_bootstrap_secret(),
        "ACCEPTED is not ESTABLISHED yet"
    );
    let handshake_response = sends(&alice_out).remove(0);
    bob.on_message(&handshake_response, &mut pair.nonces_b, NOW)
        .unwrap();
    // ... and gone at ESTABLISHED, on each side at its own moment.
    assert_eq!(bob.state(), PairingState::Established);
    assert!(!bob.holds_bootstrap_secret());
    assert_eq!(bob.bs_hint(), None);
    alice.on_first_message();
    assert_eq!(alice.state(), PairingState::Established);
    assert!(!alice.holds_bootstrap_secret());
    // Nothing that needs BS works any more: a SAS confirmation cannot be produced.
    assert_eq!(bob.confirm_sas(NOW).err(), Some(PairingError::WrongState));
    assert_eq!(alice.confirm_sas(NOW).err(), Some(PairingError::WrongState));
}

// -- §5.5 step 2 -----------------------------------------------------------------------

#[clause("PNP-003-MUST-025")]
#[test]
fn the_sas_is_six_digits_from_hkdf_of_the_keys_salted_with_bs() {
    // Known answer, computed independently (Python): BS and identity keys of the
    // PNP-003-MUST-012 vector, EK_alice = e1 x 32, EK_bob = e2 x 32.
    //   HKDF-SHA-256(salt = BS, ikm = IK_a || IK_b || EK_a || EK_b, "ParolNet_SAS_v1", 5)
    //   = cb6536c16a; as uint40 mod 1000000 = 448362.
    let bs: [u8; 32] =
        hex::decode("71109e3bddb3be261768a8e18dd94d1c1ed740ec48406e614b18566b476eb2d6")
            .unwrap()
            .try_into()
            .unwrap();
    let ik_a: [u8; 32] = std::array::from_fn(|i| 0xA0 + (i % 16) as u8);
    let ik_b: [u8; 32] = std::array::from_fn(|i| 0x10 + (i % 16) as u8);
    let material = sas_material(&bs, &ik_a, &ik_b, &[0xE1; 32], &[0xE2; 32]).unwrap();
    assert_eq!(hex::encode(material), "cb6536c16a");
    assert_eq!(sas_digits(&material), "448362");
    assert_eq!(
        compute_sas(&bs, &ik_a, &ik_b, &[0xE1; 32], &[0xE2; 32]).unwrap(),
        "448362"
    );
    // Zero-padded to six digits: 5 bytes whose value mod 10^6 is 42.
    assert_eq!(sas_digits(&[0, 0, 0, 0, 42]), "000042");
    assert_eq!(sas_digits(&[0x00, 0x00, 0x0F, 0x42, 0x40 + 7]), "000007");

    // In a real exchange both peers get that value for their own keys: Alice is the one who
    // showed the code.
    let mut pair = Pair::new();
    let (mut bob, init2) = pair.initiate(true);
    let (alice, alice_out) = pair.respond(&init2, false).unwrap();
    let resp = sends(&alice_out).remove(0);
    bob.on_message(&resp, &mut pair.nonces_b, NOW).unwrap();
    let (i, r): (BootstrapHandshake, BootstrapHandshake) = (from_cbor(&init2), from_cbor(&resp));
    let expected = compute_sas(
        &pair.bs,
        &pair.alice.public_key_bytes(),
        &pair.bob.public_key_bytes(),
        &r.ek.clone().try_into().unwrap(),
        &i.ek.clone().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(alice.sas().unwrap().digits, expected);
    assert_eq!(bob.sas().unwrap().digits, expected);
    assert_eq!(expected.len(), 6);
    assert!(expected.bytes().all(|b| b.is_ascii_digit()));
}

// -- §5.5 step 4 -----------------------------------------------------------------------

#[clause("PNP-003-MUST-027")]
#[test]
fn the_emoji_sas_maps_each_of_the_five_bytes_to_one_of_256_emoji() {
    // 256 distinct emoji.
    let distinct: std::collections::HashSet<char> = SAS_EMOJI.iter().copied().collect();
    assert_eq!(distinct.len(), 256);
    assert!(
        SAS_EMOJI
            .iter()
            .all(|c| (0x1F300..0x1F700).contains(&(*c as u32)))
    );
    // Each byte selects its own entry.
    assert_eq!(
        sas_emoji(&[0, 1, 64, 128, 255]),
        [
            SAS_EMOJI[0],
            SAS_EMOJI[1],
            SAS_EMOJI[64],
            SAS_EMOJI[128],
            SAS_EMOJI[255]
        ]
    );
    assert_eq!(sas_emoji(&[0, 0, 0, 0, 0])[0], '\u{1F400}');
    // Both peers of an exchange show the same five emoji, of the same material as the digits.
    let mut pair = Pair::new();
    let (alice, bob, _, _) = pair.authenticated(true, false);
    let (a, b) = (alice.sas().unwrap(), bob.sas().unwrap());
    assert_eq!(a.emoji, b.emoji);
    assert_eq!(a.emoji.len(), 5);
    assert!(a.emoji.iter().all(|e| SAS_EMOJI.contains(e)));
}

// -- §5.5 steps 1, 3, 5, 6 ----------------------------------------------------------------

#[clause("PNP-003-MAY-002", "PNP-003-MUST-026")]
#[test]
fn a_sas_requested_by_either_peer_is_handed_to_both_for_display() {
    for (bob_requests, alice_requests) in [(true, false), (false, true), (true, true)] {
        let mut pair = Pair::new();
        let (alice, bob, alice_out, bob_out) = pair.authenticated(bob_requests, alice_requests);
        let shown = |outputs: &[PairingOutput]| {
            outputs.iter().find_map(|o| match o {
                PairingOutput::ShowSas(sas) => Some(sas.clone()),
                _ => None,
            })
        };
        // Both sides are told to show it, and it is the same on both.
        let (a, b) = (shown(&alice_out).unwrap(), shown(&bob_out).unwrap());
        assert_eq!(a, b);
        assert_eq!(alice.state(), PairingState::SasPending);
        assert_eq!(bob.state(), PairingState::SasPending);
        // While it is pending the PNP-002 handshake has not started.
        assert!(sends(&bob_out).is_empty());
    }
    // Requested by neither: nothing to show, straight on.
    let mut pair = Pair::new();
    let (alice, bob, alice_out, bob_out) = pair.authenticated(false, false);
    assert!(!alice.sas_requested() && !bob.sas_requested());
    assert!(
        !alice_out
            .iter()
            .chain(&bob_out)
            .any(|o| matches!(o, PairingOutput::ShowSas(_)))
    );
}

#[clause("PNP-003-MUST-028")]
#[test]
fn confirming_the_sas_sends_a_sas_verify_message() {
    // sas_mac known answer (Python hmac): HMAC-SHA-256(BS, "448362" || "confirm").
    let bs: [u8; 32] =
        hex::decode("71109e3bddb3be261768a8e18dd94d1c1ed740ec48406e614b18566b476eb2d6")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        hex::encode(sas_mac(&bs, "448362")),
        "bf17a8cd56d6131c10101b8fda770fa9fa9c668dd61265a9badaacdfa51d04f3"
    );

    let mut pair = Pair::new();
    let (mut alice, mut bob, _, _) = pair.authenticated(true, false);
    for (who, pairing) in [("alice", &mut alice), ("bob", &mut bob)] {
        let digits = pairing.sas().unwrap().digits.clone();
        let out = pairing.confirm_sas(NOW).unwrap();
        let messages = sends(&out);
        assert_eq!(messages.len(), 1, "{who} sends exactly its SASVerify");
        assert_eq!(message_type(&messages[0]), Some(SAS_CONFIRM));
        assert_eq!(SAS_CONFIRM, 0x12);
        let msg: SasVerify = from_cbor(&messages[0]);
        assert_eq!(
            msg.sas_mac,
            hmac_sha256(&pair.bs, &[digits.as_bytes(), b"confirm"])
        );
        assert_eq!(msg.nonce.len(), 16);
        // Confirming is said once.
        assert_eq!(
            pairing.confirm_sas(NOW).err(),
            Some(PairingError::WrongState)
        );
    }
    // Without a confirmation nothing is sent: a pairing with no SAS in play refuses.
    let mut pair = Pair::new();
    let (mut alice, _bob, _, _) = pair.authenticated(false, false);
    assert_eq!(alice.confirm_sas(NOW).err(), Some(PairingError::WrongState));
}

#[clause("PNP-003-MUST-029")]
#[test]
fn contact_is_established_only_after_both_sas_confirmations_verified() {
    let mut pair = Pair::new();
    let (mut alice, mut bob, _, _) = pair.authenticated(true, true);

    // Bob confirms. Alice has Bob's SASVerify but has not confirmed herself: still pending.
    let bob_verify = sends(&bob.confirm_sas(NOW).unwrap()).remove(0);
    assert!(bob.awaiting_peer_confirmation());
    let out = alice
        .on_message(&bob_verify, &mut pair.nonces_a, NOW)
        .unwrap();
    assert!(out.is_empty());
    assert_eq!(alice.state(), PairingState::SasPending);
    assert_eq!(bob.state(), PairingState::SasPending);

    // Alice confirms: she has both now. Bob gets her SASVerify and only then starts PNP-002.
    let alice_out = alice.confirm_sas(NOW).unwrap();
    assert_eq!(alice.state(), PairingState::Handshaking);
    let alice_verify = sends(&alice_out).remove(0);
    let bob_out = bob
        .on_message(&alice_verify, &mut pair.nonces_b, NOW)
        .unwrap();
    assert_eq!(bob.state(), PairingState::Handshaking);
    let handshake_init = sends(&bob_out).remove(0);
    assert_eq!(message_type(&handshake_init), Some(HANDSHAKE_INIT));
    // ... and the session that follows is marked SAS-verified on both sides.
    let alice_out = alice
        .on_message(&handshake_init, &mut pair.nonces_a, NOW)
        .unwrap();
    let bob_out = bob
        .on_message(&sends(&alice_out).remove(0), &mut pair.nonces_b, NOW)
        .unwrap();
    assert_eq!(established(&bob_out), Some(true));
    assert_eq!(established(&alice.on_first_message()), Some(true));

    // A SASVerify whose MAC does not verify (the two saw different codes): abort, all erased.
    let mut pair = Pair::new();
    let (mut alice, mut bob, _, _) = pair.authenticated(true, false);
    let mut forged: SasVerify = from_cbor(&sends(&bob.confirm_sas(NOW).unwrap())[0]);
    forged.sas_mac = sas_mac(&pair.bs, "000000").to_vec();
    assert_eq!(
        alice
            .on_message(&to_cbor(&forged), &mut pair.nonces_a, NOW)
            .err(),
        Some(PairingError::SasMismatch)
    );
    assert_eq!(alice.state(), PairingState::Aborted);
    assert!(!alice.holds_bootstrap_secret());

    // A peer that skips ahead to PNP-002 while the SAS is open gets nowhere.
    let mut pair = Pair::new();
    let (mut alice, _bob, _, _) = pair.authenticated(true, false);
    let mut other = Pair::new();
    let (_a2, _b2, _, other_bob_out) = other.authenticated(false, false);
    let stray_init = sends(&other_bob_out).remove(0);
    assert!(
        alice
            .on_message(&stray_init, &mut pair.nonces_a, NOW)
            .is_err()
    );
    assert_eq!(alice.state(), PairingState::Aborted);

    // The user rejecting the SAS aborts as well.
    let mut pair = Pair::new();
    let (mut alice, _bob, _, _) = pair.authenticated(false, true);
    alice.reject_sas();
    assert_eq!(alice.state(), PairingState::Aborted);
    assert!(!alice.holds_bootstrap_secret());
}

// -- §6.4 replay --------------------------------------------------------------------------

#[clause("PNP-003-MUST-043")]
#[test]
fn a_bootstrap_handshake_with_a_nonce_seen_in_the_last_hour_is_rejected() {
    assert_eq!(NONCE_WINDOW_SECS, 60 * 60);
    // The window itself.
    let mut tracker = NonceTracker::default();
    let t0 = 1_800_000_000u64;
    let nonce = [9u8; 16];
    assert!(tracker.check_and_record(&nonce, t0));
    assert!(!tracker.check_and_record(&nonce, t0), "at once");
    assert!(
        !tracker.check_and_record(&nonce, t0 + 59 * 60),
        "after 59 minutes"
    );
    assert!(
        !tracker.check_and_record(&nonce, t0 + 3599),
        "one second short of the hour"
    );
    assert!(
        tracker.check_and_record(&[8u8; 16], t0 + 3599),
        "another nonce is fine"
    );
    assert!(
        tracker.check_and_record(&nonce, t0 + 3600),
        "after the hour it is new again"
    );
    // Being full never makes room by forgetting a nonce that is still in its window.
    let mut small = NonceTracker::new(2);
    assert!(small.check_and_record(&[1; 16], t0));
    assert!(small.check_and_record(&[2; 16], t0 + 1));
    assert!(
        !small.check_and_record(&[3; 16], t0 + 2),
        "full: refused, not evicting"
    );
    assert!(
        !small.check_and_record(&[1; 16], t0 + 3),
        "the first nonce is still known"
    );
    assert!(
        small.check_and_record(&[3; 16], t0 + 3601),
        "room again once one expired"
    );

    // The receiver of a BOOTSTRAP_INIT: the same message again is a replay, although its
    // proof verifies.
    let mut pair = Pair::new();
    let (_bob, init) = pair.initiate(false);
    assert!(pair.respond(&init, false).is_ok());
    assert_eq!(pair.respond(&init, false).err(), Some(PairingError::Replay));
    // Also with a proof made anew for the reused nonce, 59 minutes later.
    let (_bob2, other) = pair.initiate(false);
    let mut reused: BootstrapHandshake = from_cbor(&other);
    let seen: BootstrapHandshake = from_cbor(&init);
    reused.nonce = seen.nonce.clone();
    reused.proof = hmac_sha256(&pair.bs, &[&reused.ik, &reused.ek, &reused.nonce]).to_vec();
    let later = NOW + 59 * 60 * 1000;
    let replayed = Pairing::respond(
        &pair.alice,
        &BootstrapKey::Seed(&SEED),
        &to_cbor(&reused),
        None,
        &mut pair.nonces_a,
        false,
        later,
    );
    assert_eq!(replayed.err(), Some(PairingError::Replay));
    // After the hour the tracker has forgotten it.
    let much_later = NOW + 61 * 60 * 1000;
    assert!(
        Pairing::respond(
            &pair.alice,
            &BootstrapKey::Seed(&SEED),
            &to_cbor(&reused),
            None,
            &mut pair.nonces_a,
            false,
            much_later,
        )
        .is_ok()
    );

    // The receiver of a BOOTSTRAP_RESP checks its nonce the same way.
    let mut pair = Pair::new();
    let (mut bob, init) = pair.initiate(false);
    let (_alice, out) = pair.respond(&init, false).unwrap();
    let resp = sends(&out).remove(0);
    let seen: BootstrapHandshake = from_cbor(&resp);
    let nonce: [u8; 16] = seen.nonce.clone().try_into().unwrap();
    assert!(pair.nonces_b.check_and_record(&nonce, NOW / 1000 - 10));
    assert_eq!(
        bob.on_message(&resp, &mut pair.nonces_b, NOW).err(),
        Some(PairingError::Replay)
    );
    assert_eq!(bob.state(), PairingState::Aborted);
}

// -- §4 timeouts (the state table; no clause id of its own) ---------------------------------

#[test]
fn state_timeouts_abort_and_erase() {
    assert_eq!(SECRET_SHARED_TIMEOUT_MS, 5 * 60 * 1000);
    assert_eq!(SAS_TIMEOUT_MS, 10 * 60 * 1000);
    assert_eq!(HANDSHAKE_TIMEOUT_MS, 60 * 1000);

    // SECRET_SHARED: 5 minutes.
    let pair = Pair::new();
    let (mut bob, _init) = pair.initiate(false);
    assert!(
        bob.check_timeout(NOW + SECRET_SHARED_TIMEOUT_MS - 1)
            .is_ok()
    );
    assert_eq!(
        bob.check_timeout(NOW + SECRET_SHARED_TIMEOUT_MS).err(),
        Some(PairingError::Timeout)
    );
    assert_eq!(bob.state(), PairingState::Aborted);
    assert!(!bob.holds_bootstrap_secret());

    // SAS_PENDING: 10 minutes.
    let mut pair = Pair::new();
    let (mut alice, _bob, _, _) = pair.authenticated(true, false);
    assert!(alice.check_timeout(NOW + SAS_TIMEOUT_MS - 1).is_ok());
    assert!(alice.check_timeout(NOW + SAS_TIMEOUT_MS).is_err());
    assert!(!alice.holds_bootstrap_secret());

    // PNP-002 handshake: 60 seconds.
    let mut pair = Pair::new();
    let (mut alice, mut bob, _, _) = pair.authenticated(false, false);
    assert!(bob.check_timeout(NOW + HANDSHAKE_TIMEOUT_MS - 1).is_ok());
    assert!(bob.check_timeout(NOW + HANDSHAKE_TIMEOUT_MS).is_err());
    assert!(alice.check_timeout(NOW + HANDSHAKE_TIMEOUT_MS).is_err());

    // An established pairing does not time out.
    let mut pair = Pair::new();
    let (_alice, mut bob, _, _) = establish(&mut pair);
    assert!(bob.check_timeout(NOW + 24 * 3600 * 1000).is_ok());
    assert_eq!(bob.state(), PairingState::Established);
}
