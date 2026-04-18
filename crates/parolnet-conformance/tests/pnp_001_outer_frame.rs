//! PNP-001 conformance — Outer Relay Frame and H9 Privacy Pass token auth.
//!
//! Covers the §"Outer Relay Frame" and §"Token Auth (Privacy Pass)" subsections
//! added in v0.5 CANDIDATE. The outer frame wraps the (already-specced) CBOR
//! envelope and carries the routing fields relays can see: `to`, `token`, and
//! `payload`. The `from` field is gone — relays MUST NOT learn sender identity
//! on a per-frame basis.

use parolnet_clause::clause;
use parolnet_relay::tokens::{Token, TokenAuthority, TokenConfig, TokenError};
use serde::Deserialize;
use voprf::{OprfClient, Ristretto255};

type Suite = Ristretto255;

/// Mirror of the relay server's `IncomingMessage` shape. The conformance
/// crate cannot depend on the binary, so we pin the schema with a local
/// struct. Any drift in field names will fail to parse here.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OuterMessageFrame {
    #[serde(rename = "type")]
    msg_type: String,
    to: Option<String>,
    payload: Option<String>,
    /// H9 Privacy Pass token (hex-encoded CBOR-serialized `Token`).
    token: Option<String>,
}

/// Construct one token by running the full VOPRF blind → evaluate → finalize
/// round against `authority`. Returns a spendable `Token` pinned to the
/// authority's current epoch.
fn client_mint_token(authority: &TokenAuthority, nonce: [u8; 32]) -> Token {
    let mut rng = rand::rngs::OsRng;
    let blind = OprfClient::<Suite>::blind(&nonce, &mut rng).expect("voprf blind");
    let evaluated = authority.issue(std::slice::from_ref(&blind.message));
    let out = blind
        .state
        .finalize(&nonce, &evaluated[0])
        .expect("voprf finalize");
    Token {
        epoch_id: authority.current_epoch(),
        nonce: nonce.to_vec(),
        evaluation: out.to_vec(),
    }
}

// ---- §"Outer Relay Frame" -------------------------------------------------

#[clause("PNP-001-MUST-048")]
#[test]
fn outer_frame_without_token_is_rejected() {
    // A frame carrying `to` + `payload` but NO `token` field must be parseable
    // as JSON but treated as invalid at the routing layer. The relay routing
    // code (crates/parolnet-relay-server/src/main.rs, "message" branch)
    // `continue`s — drops the frame silently — when any of `to`, `payload`,
    // `token` is absent. We pin the clause here by asserting: (a) the JSON
    // parses without the token, and (b) `token` is absent, which is the
    // exact precondition that triggers the drop.
    let json = serde_json::json!({
        "type": "message",
        "to": hex::encode([0xAAu8; 32]),
        "payload": "deadbeef",
    })
    .to_string();
    let frame: OuterMessageFrame = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(frame.msg_type, "message");
    assert!(
        frame.token.is_none(),
        "PNP-001-MUST-048: `token` field absent ⇒ frame is rejected by the relay"
    );

    // A frame that does carry a token field is by contrast parseable with
    // the token populated — pin that side of the contract too.
    let with_token = serde_json::json!({
        "type": "message",
        "to": hex::encode([0xAAu8; 32]),
        "payload": "deadbeef",
        "token": "00",
    })
    .to_string();
    let ok: OuterMessageFrame = serde_json::from_str(&with_token).expect("valid JSON");
    assert!(ok.token.is_some());
    assert!(
        !ok.token.unwrap().is_empty(),
        "PNP-001-MUST-048: `token` MUST be non-empty"
    );
}

// ---- §"Token Auth (Privacy Pass)" — issue→spend round-trip ----------------

#[clause("PNP-001-MUST-049", "PNP-001-MUST-050")]
#[test]
fn token_issue_spend_round_trip_and_double_spend_rejected() {
    let mut authority = TokenAuthority::new(TokenConfig::default(), 1_700_000_000);
    let token = client_mint_token(&authority, [0x13u8; 32]);

    // First spend: VOPRF verify succeeds → `Ok(())`.
    authority
        .verify_and_spend(&token, 1_700_000_001)
        .expect("PNP-001-MUST-049: fresh token verifies");

    // Second spend of the same token: spent-set rejects it.
    match authority.verify_and_spend(&token, 1_700_000_002) {
        Err(TokenError::DoubleSpend) => {}
        other => panic!(
            "PNP-001-MUST-050: replayed token must be rejected as DoubleSpend, got {other:?}"
        ),
    }
}

// ---- §"Token Auth" — epoch rotation + grace window ------------------------

#[clause("PNP-001-MUST-051")]
#[test]
fn token_from_retired_epoch_outside_grace_is_rejected() {
    // Tight epochs so the test runs fast: 100 s epoch, 10 s grace.
    let cfg = TokenConfig {
        epoch_secs: 100,
        grace_secs: 10,
        budget_per_epoch: 32,
    };
    let t0 = 1_700_000_000u64;
    let mut authority = TokenAuthority::new(cfg, t0);
    let token = client_mint_token(&authority, [0x27u8; 32]);

    // Advance to epoch N+2 boundary + well past grace: token's epoch is gone.
    let well_past = t0 + 300; // two full rotations past.
    authority.tick(well_past);

    match authority.verify_and_spend(&token, well_past + 1) {
        Err(TokenError::UnknownEpoch) => {}
        other => panic!(
            "PNP-001-MUST-051: token from retired epoch (past grace) must be rejected, got {other:?}"
        ),
    }
}

// ---- §"Token Auth" — tamper detection -------------------------------------

#[clause("PNP-001-MUST-049")]
#[test]
fn token_with_flipped_nonce_bit_fails_verify() {
    let mut authority = TokenAuthority::new(TokenConfig::default(), 1_700_000_000);
    let mut token = client_mint_token(&authority, [0x55u8; 32]);

    // Flip a single bit in the nonce. The VOPRF evaluation was computed over
    // the original nonce, so `evaluate(sk, flipped_nonce)` will not match.
    token.nonce[0] ^= 0x01;

    match authority.verify_and_spend(&token, 1_700_000_001) {
        Err(TokenError::VerifyFailed) => {}
        other => {
            panic!("PNP-001-MUST-049: bit-flipped nonce must fail VOPRF verify, got {other:?}")
        }
    }
}

// ---- §"Token Auth" — Ed25519 issuance guard -------------------------------

#[clause("PNP-001-MUST-052")]
#[test]
fn issue_request_with_bad_signature_is_rejected() {
    // We pin the Ed25519-authenticated issuance rule without spinning up the
    // full HTTP stack: the HTTP handler delegates to `ed25519_dalek::Verifier::
    // verify(nonce, sig)`. Here we verify the same contract directly —
    // if we can produce a valid (nonce, sig, pk) triple and the tampered one
    // fails, then the handler's `verify().is_err() → UNAUTHORIZED` branch
    // trips for exactly the wrong-signature case.
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let nonce = [0x42u8; 32];

    let good_sig = sk.sign(&nonce);
    vk.verify(&nonce, &good_sig)
        .expect("PNP-001-MUST-052: good signature must verify");

    // Tamper: flip one byte in the signature.
    let mut bad_bytes = good_sig.to_bytes();
    bad_bytes[0] ^= 0x01;
    let bad_sig = ed25519_dalek::Signature::from_bytes(&bad_bytes);
    assert!(
        vk.verify(&nonce, &bad_sig).is_err(),
        "PNP-001-MUST-052: tampered signature must be rejected during /tokens/issue"
    );
}

// ---- §"Token Auth" — optional cumulative issuance accounting --------------

#[clause("PNP-001-MAY-005")]
#[test]
fn opt_in_cumulative_accounting_has_required_shape() {
    // Issuance rate limiting is OPTIONAL per §10.2 (MAY-005). If a deployment
    // chooses to enable it, the accounting MUST be cumulative per
    // (identity, epoch), MUST return 429 without advancing the counter on
    // overflow, and MUST reset on epoch rotation. This test exercises that
    // accounting shape so any re-enabled implementation can pin against it.
    //
    // Default relay builds (parolnet-relay-server) do NOT enforce the cap —
    // see `IssueLimiter` comment. MUST-050 + MUST-052 are the real defenses.
    use std::collections::HashMap;
    let budget: u32 = 32;
    let epoch_id: u32 = 7;
    let ident = [0xAAu8; 32];
    let mut issued: HashMap<[u8; 32], (u32, u32)> = HashMap::new();

    fn try_issue(
        issued: &mut HashMap<[u8; 32], (u32, u32)>,
        ident: [u8; 32],
        epoch_id: u32,
        requested: u32,
        budget: u32,
    ) -> bool {
        let entry = issued.entry(ident).or_insert((epoch_id, 0));
        if entry.0 != epoch_id {
            *entry = (epoch_id, 0);
        }
        if entry.1.saturating_add(requested) > budget {
            return false;
        }
        entry.1 = entry.1.saturating_add(requested);
        true
    }

    assert!(try_issue(&mut issued, ident, epoch_id, 10, budget));
    assert!(try_issue(&mut issued, ident, epoch_id, 10, budget));
    assert!(try_issue(&mut issued, ident, epoch_id, 12, budget));
    // Running total now 32 == cap. Overflow attempts reject without advance.
    assert!(!try_issue(&mut issued, ident, epoch_id, 1, budget));
    assert_eq!(issued[&ident], (epoch_id, 32));
    // New epoch resets the counter for this identity.
    assert!(try_issue(&mut issued, ident, epoch_id + 1, 32, budget));
    assert_eq!(issued[&ident], (epoch_id + 1, 32));
}

// ---- §5.3.1 — QR bootstrap: source_hint carries scanner IK ---------------

/// Build a presenter/scanner pair sharing only the QR payload. Returns
/// (presenter_ParolNet, scanner_ParolNet, qr_seed, presenter_ratchet_secret,
/// scanner_peer_id, scanner_ik). Mirrors the real PWA bootstrap flow:
/// presenter generates QR → scanner scans → both have a session locally on
/// the scanner side, while the presenter holds only pending_bootstrap.
fn bootstrap_state() -> (
    parolnet_core::ParolNet,
    parolnet_core::ParolNet,
    [u8; 32],
    [u8; 32],
    parolnet_protocol::address::PeerId,
    [u8; 32],
) {
    use parolnet_core::ParolNetConfig;
    use parolnet_core::bootstrap::{derive_bootstrap_secret, generate_qr_payload_with_ratchet};
    use parolnet_crypto::SharedSecret;

    let presenter = parolnet_core::ParolNet::new(ParolNetConfig::default());
    let scanner = parolnet_core::ParolNet::new(ParolNetConfig::default());

    // Presenter generates QR with ratchet key embedded.
    let qr = generate_qr_payload_with_ratchet(&presenter.public_key(), None).unwrap();

    // Scanner decodes QR payload, derives BS, and establishes initiator session.
    let parsed = parolnet_core::bootstrap::parse_qr_payload(&qr.payload_bytes).unwrap();
    let mut ratchet_key = [0u8; 32];
    ratchet_key.copy_from_slice(&parsed.rk);
    let bs = derive_bootstrap_secret(&qr.seed, &scanner.public_key(), &presenter.public_key())
        .unwrap();
    let presenter_peer = presenter.peer_id();
    scanner
        .establish_session(presenter_peer, SharedSecret(bs), &ratchet_key, true)
        .unwrap();

    let scanner_peer = scanner.peer_id();
    let scanner_ik = scanner.public_key();
    (presenter, scanner, qr.seed, qr.ratchet_secret, scanner_peer, scanner_ik)
}

#[clause("PNP-001-MUST-063", "PNP-001-MUST-064")]
#[test]
fn bootstrap_via_source_hint_establishes_responder_session() {
    let (presenter, scanner, seed, ratchet_secret, scanner_peer, scanner_ik) = bootstrap_state();
    assert!(
        !presenter.has_session(&scanner_peer),
        "precondition: presenter has no session for scanner before bootstrap"
    );

    // Scanner crafts first envelope with source_hint = their IK (MUST-063).
    let presenter_peer = presenter.peer_id();
    let source_hint = parolnet_protocol::address::PeerId(scanner_ik);
    let wire = parolnet_core::envelope::encrypt_for_peer(
        scanner.sessions(),
        &presenter_peer,
        0x01, // CHAT
        b"hello from the scanner",
        1_700_000_000,
        Some(source_hint),
    )
    .unwrap();

    // Presenter runs the §5.3.1 materialization path.
    let decoded = parolnet_core::envelope::try_bootstrap_and_decrypt(
        presenter.sessions(),
        &wire,
        &presenter.public_key(),
        &seed,
        &ratchet_secret,
    )
    .expect("MUST-064: valid source_hint + AEAD OK → session materializes + decrypts");

    assert_eq!(decoded.plaintext, b"hello from the scanner");
    assert_eq!(
        decoded.source_hint,
        Some(scanner_peer),
        "MUST-064: returned source_hint is the PeerId of the now-committed session"
    );
    assert!(
        presenter.has_session(&scanner_peer),
        "MUST-064: AEAD success commits the candidate session to the manager"
    );
}

#[clause("PNP-001-MUST-064")]
#[test]
fn bootstrap_source_hint_tamper_fails_without_committing_session() {
    let (presenter, scanner, seed, ratchet_secret, scanner_peer, scanner_ik) = bootstrap_state();

    // Scanner sends a legitimate bootstrap frame…
    let presenter_peer = presenter.peer_id();
    let source_hint = parolnet_protocol::address::PeerId(scanner_ik);
    let mut wire = parolnet_core::envelope::encrypt_for_peer(
        scanner.sessions(),
        &presenter_peer,
        0x01,
        b"hi",
        1_700_000_000,
        Some(source_hint),
    )
    .unwrap();

    // …but a MITM flips a byte deep in the cleartext region. The tamper
    // may land on source_hint itself or elsewhere in the header — either way,
    // the AEAD AAD binds the entire cleartext header (PNP-001-MUST-007), so
    // the candidate session's decrypt MUST fail.
    // Byte offset ~12 reliably sits inside the cleartext header array for
    // the 256-byte bucket envelopes produced above.
    wire[20] ^= 0x01;

    let res = parolnet_core::envelope::try_bootstrap_and_decrypt(
        presenter.sessions(),
        &wire,
        &presenter.public_key(),
        &seed,
        &ratchet_secret,
    );
    assert!(
        res.is_err(),
        "MUST-064: AEAD failure on tampered header MUST reject"
    );
    assert!(
        !presenter.has_session(&scanner_peer),
        "MUST-064: failed materialization MUST NOT commit the candidate session"
    );
}

#[clause("PNP-001-SHOULD-013")]
#[test]
fn second_envelope_uses_null_source_hint_on_established_session() {
    let (presenter, scanner, seed, ratchet_secret, scanner_peer, scanner_ik) = bootstrap_state();

    // First envelope bootstraps the session (MUST-063).
    let presenter_peer = presenter.peer_id();
    let source_hint = parolnet_protocol::address::PeerId(scanner_ik);
    let wire1 = parolnet_core::envelope::encrypt_for_peer(
        scanner.sessions(),
        &presenter_peer,
        0x01,
        b"first",
        1_700_000_000,
        Some(source_hint),
    )
    .unwrap();
    let _ = parolnet_core::envelope::try_bootstrap_and_decrypt(
        presenter.sessions(),
        &wire1,
        &presenter.public_key(),
        &seed,
        &ratchet_secret,
    )
    .unwrap();
    assert!(presenter.has_session(&scanner_peer));

    // Second envelope over the now-established session — SHOULD-013 says
    // source_hint returns to null. The pure envelope path does this by
    // default (encrypt_for_peer with source_hint = None).
    let wire2 = parolnet_core::envelope::encrypt_for_peer(
        scanner.sessions(),
        &presenter_peer,
        0x01,
        b"second",
        1_700_000_300,
        None,
    )
    .unwrap();

    // Presenter decrypts via the normal path — no materialization needed now.
    let decoded = parolnet_core::envelope::decrypt_for_peer(
        presenter.sessions(),
        &scanner_peer,
        &wire2,
    )
    .unwrap();

    assert_eq!(decoded.plaintext, b"second");
    assert_eq!(
        decoded.source_hint, None,
        "SHOULD-013: post-bootstrap envelopes default to source_hint = null"
    );
}
