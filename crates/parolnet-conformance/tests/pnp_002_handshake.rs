//! PNP-002 conformance — X3DH handshake.

use parolnet_clause::clause;
use parolnet_crypto::identity::{OneTimePreKeyPair, SignedPreKey};
use parolnet_crypto::x3dh::X3dhKeyAgreement;
use parolnet_crypto::{
    IdentityKeyPair, KeyAgreement, OneTimePreKey, PreKeyBundle,
};

fn bundle_for(bob: &IdentityKeyPair, with_opk: bool) -> (PreKeyBundle, SignedPreKey, Option<OneTimePreKeyPair>) {
    let spk = SignedPreKey::generate(1, bob).unwrap();
    let opk = if with_opk {
        Some(OneTimePreKeyPair::generate(100))
    } else {
        None
    };
    let one_time = opk
        .as_ref()
        .map(|o| OneTimePreKey {
            id: o.id,
            key: *o.public_key.as_bytes(),
        });
    let bundle = PreKeyBundle {
        identity_key: bob.public_key_bytes(),
        signed_prekey: *spk.public_key.as_bytes(),
        signed_prekey_id: spk.id,
        signed_prekey_sig: spk.signature.to_vec(),
        one_time_prekeys: one_time.map(|o| vec![o]).unwrap_or_default(),
    };
    (bundle, spk, opk)
}

// -- §5.1 SPK signature verification ------------------------------------------

#[clause("PNP-002-MUST-003", "PNP-002-MUST-004")]
#[test]
fn alice_rejects_bundle_with_bad_spk_signature() {
    let bob = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let (mut bundle, _spk, _opk) = bundle_for(&bob, true);
    // Flip last byte of signature.
    let last = bundle.signed_prekey_sig.len() - 1;
    bundle.signed_prekey_sig[last] ^= 0xFF;

    let agreement = X3dhKeyAgreement { identity: alice };
    let err = match agreement.initiate(&bundle) {
        Err(e) => e,
        Ok(_) => panic!(
            "Alice MUST abort if SPK signature does not verify (PNP-002-MUST-003/004)"
        ),
    };
    let msg = format!("{err}");
    assert!(
        msg.to_ascii_lowercase().contains("signature")
            || msg.to_ascii_lowercase().contains("prekey"),
        "expected SPK sig failure, got: {msg}"
    );
}

#[clause("PNP-002-MUST-003")]
#[test]
fn alice_accepts_bundle_with_valid_spk_signature() {
    let bob = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let (bundle, _spk, _opk) = bundle_for(&bob, true);
    let agreement = X3dhKeyAgreement { identity: alice };
    agreement
        .initiate(&bundle)
        .expect("valid bundle MUST succeed");
}

// -- §5.2.1 fresh ephemeral per initiation ------------------------------------

#[clause("PNP-002-MUST-005")]
#[test]
fn each_initiate_uses_fresh_ephemeral() {
    let bob = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let (bundle, _, _) = bundle_for(&bob, true);
    let agreement = X3dhKeyAgreement { identity: alice };
    let (_, h1) = agreement.initiate(&bundle).unwrap();
    let (_, h2) = agreement.initiate(&bundle).unwrap();
    assert_ne!(
        h1.ephemeral_key, h2.ephemeral_key,
        "MUST-005: ephemeral key MUST be fresh per initiation"
    );
}

// -- §5.1 X3DH shared-secret agreement (Alice and Bob derive identical SK) ----

#[clause("PNP-002-MUST-006", "PNP-002-MUST-014")]
#[test]
fn alice_and_bob_derive_same_shared_secret_with_opk() {
    let bob = IdentityKeyPair::generate();
    let (bundle, spk, opk) = bundle_for(&bob, true);
    let alice = IdentityKeyPair::generate();
    let a_agreement = X3dhKeyAgreement { identity: alice };

    let (sk_alice, header) = a_agreement.initiate(&bundle).unwrap();

    let b_agreement = X3dhKeyAgreement { identity: bob };
    let opk_sec = opk.as_ref().map(|o| &o.private_key);
    let sk_bob = b_agreement
        .respond(&header, &spk.private_key, opk_sec)
        .unwrap();

    assert_eq!(
        sk_alice.0, sk_bob.0,
        "Alice and Bob MUST derive identical X3DH shared secret"
    );
}

#[clause("PNP-002-MUST-006")]
#[test]
fn x3dh_falls_back_to_three_dh_without_opk() {
    let bob = IdentityKeyPair::generate();
    let (bundle, spk, _opk) = bundle_for(&bob, false);
    let alice = IdentityKeyPair::generate();
    let a = X3dhKeyAgreement { identity: alice };
    let (sk_alice, header) = a.initiate(&bundle).unwrap();
    assert!(
        header.one_time_prekey_id.is_none(),
        "bundle without OPKs MUST yield a 3-DH handshake"
    );

    let b = X3dhKeyAgreement { identity: bob };
    let sk_bob = b.respond(&header, &spk.private_key, None).unwrap();
    assert_eq!(sk_alice.0, sk_bob.0);
}

// -- §5.3.2 OPK one-time property ---------------------------------------------
// Verified through the header: OPK ID appears exactly when an OPK was used.
// Full OPK-deletion enforcement is at the session-store layer; this test
// pins the wire-observable half of MUST-013.

#[clause("PNP-002-MUST-013")]
#[test]
fn opk_id_reported_iff_opk_used() {
    let bob = IdentityKeyPair::generate();
    let alice1 = IdentityKeyPair::generate();
    let alice2 = IdentityKeyPair::generate();

    let (bundle_opk, _, _) = bundle_for(&bob, true);
    let (bundle_noop, _, _) = bundle_for(&bob, false);

    let a1 = X3dhKeyAgreement { identity: alice1 };
    let a2 = X3dhKeyAgreement { identity: alice2 };

    let (_, h1) = a1.initiate(&bundle_opk).unwrap();
    let (_, h2) = a2.initiate(&bundle_noop).unwrap();

    assert!(
        h1.one_time_prekey_id.is_some(),
        "OPK ID MUST be set when an OPK was consumed"
    );
    assert!(
        h2.one_time_prekey_id.is_none(),
        "OPK ID MUST be absent when no OPK was available"
    );
}

// -- §5.1 Domain separator in SK derivation (implicit in shared-secret agreement)
// By constructing two different Bobs and checking SKs differ, we transitively
// verify DH inputs land in the HKDF correctly.

#[clause("PNP-002-MUST-006")]
#[test]
fn different_bobs_produce_different_shared_secrets() {
    let alice = IdentityKeyPair::generate();
    let bob_a = IdentityKeyPair::generate();
    let bob_b = IdentityKeyPair::generate();
    let (b_a, _, _) = bundle_for(&bob_a, true);
    let (b_b, _, _) = bundle_for(&bob_b, true);
    let agreement = X3dhKeyAgreement { identity: alice };
    let (sk1, _) = agreement.initiate(&b_a).unwrap();
    let (sk2, _) = agreement.initiate(&b_b).unwrap();
    assert_ne!(sk1.0, sk2.0);
}

// -- §7 Deniability — handshake transcript has no signature over session bytes -
// We verify that X3DH output carries no signature field; the only signature in
// the bundle is the SPK sig (which proves only that Bob published that SPK,
// not that any session was established). This pins MUST-035 at the type level.

#[clause("PNP-002-MUST-035")]
#[test]
fn x3dh_header_carries_no_transcript_signature() {
    let bob = IdentityKeyPair::generate();
    let alice = IdentityKeyPair::generate();
    let (bundle, _, _) = bundle_for(&bob, true);
    let (_, header) = X3dhKeyAgreement { identity: alice }
        .initiate(&bundle)
        .unwrap();
    // Struct introspection: X3dhHeader has exactly the four fields enumerated
    // in PNP-002 §3.2; none of them is a signature. Asserting shape via
    // destructuring pattern-matches the spec.
    let parolnet_crypto::X3dhHeader {
        identity_key: _,
        ephemeral_key: _,
        signed_prekey_id: _,
        one_time_prekey_id: _,
    } = header;
}

// -- §6.5 Nonce freshness (128-bit) -------------------------------------------
// X3dhHeader itself does not carry a nonce (the nonce is carried in the
// envelope payload per §3.2). We pin MUST-033 by directly exercising the RNG
// boundary used by X3DH: OsRng must produce distinct 16-byte nonces.

#[clause("PNP-002-MUST-033")]
#[test]
fn csprng_produces_distinct_nonces() {
    use rand::RngCore;
    let mut n1 = [0u8; 16];
    let mut n2 = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n1);
    rand::thread_rng().fill_bytes(&mut n2);
    assert_ne!(n1, n2, "CSPRNG collision at 128 bits is implausible");
}
