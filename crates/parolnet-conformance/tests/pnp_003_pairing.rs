//! PNP-003 conformance of the shipped native client, observed from outside: the real headless
//! client (`parolnet-app`) against the real relay binary and a scripted peer that either
//! scans the client's pairing code or shows one for the client to scan (see `common`).
//!
//! The clauses about what a user interface displays are tested here at the boundary the
//! interface is built on: what the core hands it to display and when it takes that away.

mod common;

use std::time::Duration;

use common::{App, RawPeer, Relay, now_secs};
use hmac::{Hmac, KeyInit, Mac};
use parolnet_app::{AppEvent, DeliveryState};
use parolnet_clause::clause;
use parolnet_core::bootstrap::pairing::{
    BOOTSTRAP_INIT, BootstrapHandshake, BootstrapKey, HANDSHAKE_INIT, HandshakeInit,
    MSG_TYPE_HANDSHAKE, Pairing, PairingOutput, PairingState, SAS_CONFIRM, SasVerify, message_type,
    sas_mac,
};
use parolnet_core::bootstrap::{self, compute_sas, parse_qr_text};
use parolnet_core::envelope::decrypt_from_envelope;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use sha2::Sha256;

const TEXT: u8 = 0x01;
const CHANNEL_BINDING: u8 = 0x14;

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    ciborium::from_reader(bytes).unwrap()
}

fn to_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn is_failed(ev: &AppEvent) -> bool {
    matches!(ev, AppEvent::PairingFailed { .. })
}

fn is_complete(ev: &AppEvent) -> bool {
    matches!(ev, AppEvent::PairingComplete { .. })
}

/// A copy of a ratchet session as it is now.
fn snapshot(session: &DoubleRatchetSession) -> DoubleRatchetSession {
    DoubleRatchetSession::import_bytes(&session.export_bytes()).unwrap()
}

/// The scripted peer scans the app's code and the pairing runs to the end, bindings
/// included: content flows afterwards.
async fn pair_as_scanner(relay: &Relay, app: &mut App) -> RawPeer {
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(relay, &code).await;
    peer.send_bootstrap();
    peer.receive(Duration::from_secs(20), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    app.wait("the pairing to complete", 20, is_complete).await;
    peer
}

// -- §5.4: the app scans a code -----------------------------------------------------

// The client that scanned sends a BootstrapHandshake as its first message, with a proof of
// the Bootstrap Secret; after the answer verifies it runs the PNP-002 handshake on the
// pre-key bundles and talks under that session.
#[clause(
    "PNP-003-MUST-020",
    "PNP-003-MUST-021",
    "PNP-003-MUST-023",
    "PNP-003-MUST-024"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scanning_client_sends_a_bootstrap_handshake_and_moves_to_pnp002() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let (mut peer, seed, first) = RawPeer::presented(&relay, &app).await;

    // MUST-020: its first message is a BOOTSTRAP_INIT in a HANDSHAKE envelope.
    assert_eq!(first.msg_type, MSG_TYPE_HANDSHAKE);
    assert_eq!(message_type(&first.plaintext), Some(BOOTSTRAP_INIT));
    let init: BootstrapHandshake = from_cbor(&first.plaintext);
    assert_eq!(init.ik, peer.app_ik);
    // MUST-021: proof = HMAC-SHA-256(BS, ik || ek || nonce), recomputed here from our own BS.
    assert_eq!(
        init.proof,
        hmac_sha256(&peer.bs, &[&init.ik, &init.ek, &init.nonce])
    );
    assert_eq!((init.ek.len(), init.nonce.len()), (32, 16));

    // We answer; the app verifies our proof and starts PNP-002 with a HandshakeInit that
    // uses the signed pre-key (and one-time pre-key) of the bundle we sent (MUST-023).
    let bootstrap_session = snapshot(&peer.session);
    peer.respond(&seed, &first.plaintext, false);
    let mut handshake_init = None;
    while handshake_init.is_none() {
        let d = peer
            .next_envelope(Duration::from_secs(20))
            .await
            .expect("the app goes on to the PNP-002 handshake");
        if d.msg_type == MSG_TYPE_HANDSHAKE {
            handshake_init = Some(d.plaintext);
        }
    }
    let handshake_init = handshake_init.unwrap();
    assert_eq!(message_type(&handshake_init), Some(HANDSHAKE_INIT));
    let parsed: HandshakeInit = from_cbor(&handshake_init);
    assert_eq!(parsed.ik_a, peer.app_ik);
    assert!(parsed.opk_id_b.is_some(), "our one-time pre-key was used");
    assert!(peer.pairing.as_ref().unwrap().holds_bootstrap_secret());
    peer.on_handshake(&handshake_init);
    assert_eq!(
        peer.pairing.as_ref().unwrap().state(),
        PairingState::Accepted
    );

    // The session's first message arrives under the PNP-002 session: the bootstrap session
    // (keyed by BS) cannot read it, the new one can.
    let bytes = peer
        .next_raw(Duration::from_secs(20))
        .await
        .expect("the first message of the PNP-002 session");
    let mut old = bootstrap_session;
    assert!(
        decrypt_from_envelope(&mut old, &bytes).is_err(),
        "the app still talks under the session keyed by the Bootstrap Secret"
    );
    decrypt_from_envelope(&mut peer.session, &bytes).expect("the PNP-002 session reads it");
    let outputs = peer.pairing.as_mut().unwrap().on_first_message();
    peer.apply(outputs);
    assert_eq!(peer.sas_verified, Some(false));

    // MUST-024: the app is done with the bootstrap. Content flows under the new session.
    app.wait("the pairing to complete", 20, is_complete).await;
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    peer.send(TEXT, b"hello from the presenter");
    let ev = app
        .wait("our text", 20, |e| matches!(e, AppEvent::Message(_)))
        .await;
    let AppEvent::Message(m) = ev else {
        unreachable!()
    };
    assert_eq!(m.text, "hello from the presenter");
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts.len(), 1);
}

// The app showed the code: it answers a BootstrapHandshake with its own, the PNP-002
// handshake follows, and a text typed while the pairing ran arrives under the new session.
#[clause("PNP-003-MUST-023", "PNP-003-MUST-050")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_presenting_client_answers_and_moves_to_pnp002() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let peer_id = peer.id.peer_id.clone();
    peer.send_bootstrap();
    app.wait("the contact", 20, |e| {
        matches!(e, AppEvent::ContactAdded(_))
    })
    .await;
    // Typed while the pairing is under way: accepted, and not sent under the session that
    // is about to be replaced.
    let held = app.handle.send_text(&peer_id, "typed early").await.unwrap();
    assert_eq!(held.state, DeliveryState::Queued);

    // The app's answer: BOOTSTRAP_RESP with its proof and a pre-key bundle it signed.
    let d = peer.next_envelope(Duration::from_secs(20)).await.unwrap();
    assert_eq!(d.msg_type, MSG_TYPE_HANDSHAKE);
    let resp: BootstrapHandshake = from_cbor(&d.plaintext);
    assert_eq!(resp.msg_type, 0x11);
    assert_eq!(resp.ik, peer.app_ik);
    assert_eq!(
        resp.proof,
        hmac_sha256(&peer.bs, &[&resp.ik, &resp.ek, &resp.nonce])
    );
    assert!(resp.prekey_bundle.verified(&peer.app_ik).is_ok());
    let bootstrap_session = snapshot(&peer.session);
    peer.on_handshake(&d.plaintext);

    // The rest of the pairing, then the bindings.
    let got = peer
        .receive(Duration::from_secs(20), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    assert_eq!(got.len(), 1);
    assert_eq!(peer.sas_verified, Some(false));
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    app.wait("the pairing to complete", 20, is_complete).await;

    // The held text comes under the PNP-002 session, which the bootstrap session cannot read.
    let bytes = peer.next_raw(Duration::from_secs(20)).await.unwrap();
    let mut old = bootstrap_session;
    assert!(decrypt_from_envelope(&mut old, &bytes).is_err());
    let text = decrypt_from_envelope(&mut peer.session, &bytes).unwrap();
    assert_eq!(
        (text.msg_type, text.plaintext.as_slice()),
        (TEXT, &b"typed early"[..])
    );

    // MUST-050: the Bootstrap Secret is gone from the app. A SAS confirmation, which needs
    // it, is no longer possible, and a handshake message under it changes nothing.
    assert!(app.handle.confirm_sas(&peer_id).await.is_err());
    let late = to_cbor(&SasVerify {
        msg_type: SAS_CONFIRM,
        sas_mac: sas_mac(&peer.bs, "000000").to_vec(),
        nonce: vec![0; 16],
    });
    peer.send(MSG_TYPE_HANDSHAKE, &late);
    peer.send(TEXT, b"still paired");
    let ev = app
        .wait("a text after the stray handshake message", 20, |e| {
            matches!(e, AppEvent::Message(m) if m.text == "still paired") || is_failed(e)
        })
        .await;
    assert!(matches!(ev, AppEvent::Message(_)));
}

// -- §5.4 step 3: a proof that does not verify ------------------------------------------

#[clause("PNP-003-MUST-022")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_proof_aborts_the_bootstrap_on_either_side() {
    let relay = Relay::start(&[]).await;

    // The app showed the code. The scanner knows the seed (its envelope decrypts) but its
    // BootstrapHandshake carries a proof that does not verify.
    let mut app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let mut bs = peer.bs;
    let (_pairing, init) = Pairing::initiate(
        &peer.id.keypair(),
        &mut bs,
        peer.app_ik,
        false,
        now_secs() * 1000,
    )
    .unwrap();
    let mut bad: BootstrapHandshake = from_cbor(&init);
    bad.proof[0] ^= 1;
    peer.send_bootstrap_payload(&to_cbor(&bad));
    let mut contact = false;
    app.wait_seeing("the pairing to fail", 20, is_failed, |e| {
        contact |= matches!(e, AppEvent::ContactAdded(_))
    })
    .await;
    assert!(
        !contact,
        "a contact was added on a proof that did not verify"
    );
    // Nothing is kept: no contact, no session (a text under the bootstrap session is not
    // read), and the code is spent, so the genuine handshake is not accepted afterwards.
    peer.send(TEXT, b"should not arrive");
    peer.send_bootstrap_payload(&init);
    let events = app.drain(Duration::from_secs(3)).await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AppEvent::Message(_) | AppEvent::ContactAdded(_))),
        "{events:?}"
    );
    let snapshot = app.handle.snapshot().await.unwrap();
    assert!(snapshot.contacts.is_empty());
    assert!(snapshot.pairing_code.is_none());
    assert!(peer.next_raw(Duration::from_secs(1)).await.is_none());

    // The app scanned our code. Our answer carries a bad proof: the app aborts, removes the
    // contact it had listed and never starts PNP-002.
    let mut app = App::start(&relay).await;
    let (mut peer, seed, first) = RawPeer::presented(&relay, &app).await;
    let peer_id = peer.id.peer_id.clone();
    assert_eq!(app.handle.snapshot().await.unwrap().contacts.len(), 1);
    let (_pairing, outputs) = Pairing::respond(
        &peer.id.keypair(),
        &BootstrapKey::Seed(&seed),
        &first.plaintext,
        Some(&peer.app_ik),
        &mut peer.nonces,
        false,
        now_secs() * 1000,
    )
    .unwrap();
    let resp = outputs
        .into_iter()
        .find_map(|o| match o {
            PairingOutput::Send(m) => Some(m),
            _ => None,
        })
        .unwrap();
    let mut bad: BootstrapHandshake = from_cbor(&resp);
    bad.proof[31] ^= 0x40;
    peer.send(MSG_TYPE_HANDSHAKE, &to_cbor(&bad));
    let mut removed = false;
    app.wait_seeing("the pairing to fail", 20, is_failed, |e| {
        removed |= matches!(e, AppEvent::ContactRemoved { peer_id: p } if *p == peer_id)
    })
    .await;
    assert!(removed, "the contact the pairing added stays listed");
    assert!(app.handle.snapshot().await.unwrap().contacts.is_empty());
    // The genuine answer comes too late: the bootstrap is over and BS is erased.
    peer.send(MSG_TYPE_HANDSHAKE, &resp);
    let mut sent = Vec::new();
    while let Some(bytes) = peer.next_raw(Duration::from_secs(2)).await {
        sent.push(bytes);
    }
    assert!(
        sent.iter()
            .all(|b| decrypt_from_envelope(&mut peer.session, b)
                .map(|d| d.msg_type != MSG_TYPE_HANDSHAKE)
                .unwrap_or(true)),
        "the app went on with the handshake after a bad proof"
    );
    assert!(app.handle.snapshot().await.unwrap().contacts.is_empty());
}

// -- §6.1 (b): one bootstrap per seed; §5.1 step 4, §7.4: the code on display ----------------

#[clause("PNP-003-MUST-040", "PNP-003-MUST-009", "PNP-003-MUST-048")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_is_good_for_one_bootstrap_and_leaves_the_display_with_it() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;

    // MUST-009: there is a code to display only between asking for one and it being used,
    // cancelled or expired.
    let before = app.handle.snapshot().await.unwrap();
    assert_eq!((before.pairing_code, before.pairing_open), (None, false));
    let code = app.handle.create_pairing_code().await.unwrap();
    let shown = app.handle.snapshot().await.unwrap();
    assert_eq!(shown.pairing_code.as_deref(), Some(code.as_str()));
    app.handle.cancel_pairing_code();
    app.wait("the code to close", 5, |e| {
        matches!(e, AppEvent::PairingCodeClosed)
    })
    .await;
    let cancelled = app.handle.snapshot().await.unwrap();
    assert_eq!(
        (cancelled.pairing_code, cancelled.pairing_open),
        (None, false)
    );

    // A new code; two peers got hold of it (one photographed the screen).
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut first = RawPeer::connect(&relay, &code).await;
    let mut second = RawPeer::connect(&relay, &code).await;
    first.send_bootstrap();
    // MUST-048: the moment a bootstrap takes the code, the app has it taken off the display.
    app.wait("the code to close", 20, |e| {
        matches!(e, AppEvent::PairingCodeClosed)
    })
    .await;
    assert_eq!(app.handle.snapshot().await.unwrap().pairing_code, None);
    first
        .receive(Duration::from_secs(20), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    let ours = first.binding().encode();
    first.send(CHANNEL_BINDING, &ours);
    app.wait("the first pairing to complete", 20, is_complete)
        .await;

    // MUST-040: the second bootstrap under the same seed is not accepted, although its
    // handshake is as valid as the first one's.
    second.send_bootstrap();
    let events = app.drain(Duration::from_secs(4)).await;
    assert!(
        !events.iter().any(|e| matches!(
            e,
            AppEvent::ContactAdded(_)
                | AppEvent::ContactUpdated(_)
                | AppEvent::PairingComplete { .. }
        )),
        "a second bootstrap was accepted for one seed: {events:?}"
    );
    assert!(
        second.next_raw(Duration::from_secs(1)).await.is_none(),
        "the app answered a second bootstrap for one seed"
    );
    let snapshot = app.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.contacts.len(), 1);
    assert_eq!(snapshot.contacts[0].contact.peer_id, first.id.peer_id);
}

// -- §5.1 step 4, §6.1 (a): expiry ------------------------------------------------------------

#[clause("PNP-003-SHOULD-001", "PNP-003-SHOULD-003")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_carries_its_expiry_and_is_shown_for_ten_minutes_at_most_by_default() {
    let relay = Relay::start(&[]).await;
    // By default: the expiry handed to the display is 10 minutes ahead.
    let app = App::start(&relay).await;
    let before = now_secs() * 1000;
    app.handle.create_pairing_code().await.unwrap();
    let shown = app.handle.snapshot().await.unwrap();
    let expires = shown
        .pairing_expires_ms
        .expect("an expiry for the indicator");
    let lifetime = expires - before;
    assert!(
        (598_000..=605_000).contains(&lifetime),
        "the code is shown for {lifetime} ms"
    );

    // A short window: at its expiry the code is no longer there to display, and it is no
    // longer accepted either.
    let mut app = App::start_with(&relay, |cfg| {
        cfg.pairing_window = Duration::from_secs(3);
    })
    .await;
    let code = app.handle.create_pairing_code().await.unwrap();
    assert!(app.handle.snapshot().await.unwrap().pairing_code.is_some());
    tokio::time::sleep(Duration::from_millis(3200)).await;
    let expired = app.handle.snapshot().await.unwrap();
    assert_eq!(
        (expired.pairing_code, expired.pairing_expires_ms),
        (None, None)
    );
    assert!(!expired.pairing_open);
    // The display is told (with the core's next housekeeping pass).
    app.wait("the code to close", 20, |e| {
        matches!(e, AppEvent::PairingCodeClosed)
    })
    .await;
    // The code itself is still young enough for a scanner (30 minutes), but the app no
    // longer waits for it: an offer from the stranger who has it gets no answer.
    assert!(parse_qr_text(&code).is_ok());
    let stranger = common::Identity::new();
    let mut ws = relay.ws().await;
    common::register(&mut ws, &stranger).await;
    common::ws_send(
        &mut ws,
        serde_json::json!({
            "type": "rtc_offer",
            "to": app.handle.peer_id(),
            "payload": serde_json::json!({"type": "offer", "sdp": "v=0\r\n"}).to_string(),
        }),
    )
    .await;
    assert!(
        common::ws_recv_type(&mut ws, "rtc_answer", Duration::from_secs(3))
            .await
            .is_none()
    );
}

// -- §6.4: replay ------------------------------------------------------------------------------

#[clause("PNP-003-MUST-043")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_rejects_a_bootstrap_handshake_nonce_it_has_seen() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;

    // A first pairing, whose BOOTSTRAP_INIT nonce we note.
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut first = RawPeer::connect(&relay, &code).await;
    let mut bs = first.bs;
    let (pairing, init) = Pairing::initiate(
        &first.id.keypair(),
        &mut bs,
        first.app_ik,
        false,
        now_secs() * 1000,
    )
    .unwrap();
    let seen: BootstrapHandshake = from_cbor(&init);
    first.pairing = Some(pairing);
    first.send_bootstrap_payload(&init);
    first
        .receive(Duration::from_secs(20), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    let ours = first.binding().encode();
    first.send(CHANNEL_BINDING, &ours);
    app.wait("the first pairing to complete", 20, is_complete)
        .await;

    // A new code. Another peer's handshake for it is valid in every respect (its proof is
    // made with the new Bootstrap Secret) except that it reuses the nonce.
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut second = RawPeer::connect(&relay, &code).await;
    let mut bs = second.bs;
    let (_pairing, init) = Pairing::initiate(
        &second.id.keypair(),
        &mut bs,
        second.app_ik,
        false,
        now_secs() * 1000,
    )
    .unwrap();
    let mut replay: BootstrapHandshake = from_cbor(&init);
    replay.nonce = seen.nonce.clone();
    replay.proof = hmac_sha256(&second.bs, &[&replay.ik, &replay.ek, &replay.nonce]);
    second.send_bootstrap_payload(&to_cbor(&replay));
    let mut contact = false;
    let ev = app
        .wait_seeing("the replayed handshake to be refused", 20, is_failed, |e| {
            contact |= matches!(e, AppEvent::ContactAdded(_))
        })
        .await;
    let AppEvent::PairingFailed { peer_id, reason } = ev else {
        unreachable!()
    };
    assert_eq!(peer_id, second.id.peer_id);
    assert!(reason.contains("nonce"), "{reason}");
    assert!(!contact);
    assert_eq!(app.handle.snapshot().await.unwrap().contacts.len(), 1);
}

// -- §5.5: SAS verification -----------------------------------------------------------------------

#[clause(
    "PNP-003-MUST-026",
    "PNP-003-MUST-028",
    "PNP-003-MUST-029",
    "PNP-003-MUST-044"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_shows_the_sas_confirms_it_and_waits_for_the_peers_confirmation() {
    let relay = Relay::start(&[]).await;
    // The app asks for SAS verification; the scanner does not, and is drawn in anyway.
    let mut app = App::start_with(&relay, |cfg| cfg.request_sas = true).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let peer_id = peer.id.peer_id.clone();
    peer.send_bootstrap();
    peer.complete_pairing().await;

    // MUST-026: the app hands its user interface the SAS to display, and it is the value
    // the other peer displays (digits and emoji), computed here from the handshake fields.
    let ev = app
        .wait("the SAS to display", 20, |e| {
            matches!(e, AppEvent::SasVerification { .. })
        })
        .await;
    let AppEvent::SasVerification {
        peer_id: shown_for,
        digits,
        emoji,
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(shown_for, peer_id);
    let ours = peer.sas.clone().expect("our side shows the SAS too");
    assert_eq!(digits, ours.digits);
    assert_eq!(emoji, ours.emoji.iter().collect::<String>());
    assert_eq!(digits.len(), 6);
    assert_eq!(emoji.chars().count(), 5);

    // Nobody confirmed: the pairing waits. No PNP-002 message, no completion.
    assert_eq!(
        peer.pairing.as_ref().unwrap().state(),
        PairingState::SasPending
    );
    let events = app.drain(Duration::from_secs(2)).await;
    assert!(!events.iter().any(is_complete));

    // MUST-028: the user confirms on the app; it sends a SASVerify with the MAC of the SAS.
    app.handle.confirm_sas(&peer_id).await.unwrap();
    let mut verify = None;
    while verify.is_none() {
        let d = peer.next_envelope(Duration::from_secs(20)).await.unwrap();
        if d.msg_type == MSG_TYPE_HANDSHAKE {
            verify = Some(d.plaintext);
        }
    }
    let verify = verify.unwrap();
    assert_eq!(message_type(&verify), Some(SAS_CONFIRM));
    let msg: SasVerify = from_cbor(&verify);
    assert_eq!(
        msg.sas_mac,
        hmac_sha256(&peer.bs, &[digits.as_bytes(), b"confirm"])
    );

    // MUST-029: its own confirmation is not enough. Until ours has arrived and verified the
    // app does not treat the contact as established.
    peer.on_handshake(&verify);
    let events = app.drain(Duration::from_secs(2)).await;
    assert!(
        !events.iter().any(is_complete),
        "established on one confirmation"
    );
    assert!(peer.pairing.as_ref().unwrap().holds_bootstrap_secret());
    // Ours: the pairing goes through and is marked SAS-verified on both sides.
    let outputs = peer
        .pairing
        .as_mut()
        .unwrap()
        .confirm_sas(now_secs() * 1000)
        .unwrap();
    peer.apply(outputs);
    peer.complete_pairing().await;
    let binding = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &binding);
    let ev = app.wait("the pairing to complete", 20, is_complete).await;
    assert_eq!(
        ev,
        AppEvent::PairingComplete {
            peer_id: peer_id.clone(),
            sas_verified: true
        }
    );
    assert_eq!(peer.sas_verified, Some(true));
    // MUST-044: with the session established the app holds no Bootstrap Secret: it cannot
    // confirm a SAS again.
    assert!(app.handle.confirm_sas(&peer_id).await.is_err());
}

#[clause("PNP-003-MUST-029")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sas_confirmation_that_does_not_verify_ends_the_pairing() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let peer_id = peer.id.peer_id.clone();
    // This time the scanner asks for the SAS.
    peer.send_bootstrap_requesting_sas(true);
    peer.complete_pairing().await;
    app.wait("the SAS to display", 20, |e| {
        matches!(e, AppEvent::SasVerification { .. })
    })
    .await;
    assert_eq!(app.handle.snapshot().await.unwrap().contacts.len(), 1);

    // A man in the middle would make the two sides see different codes: our confirmation
    // is the MAC of another SAS.
    let wrong = if peer.sas.as_ref().unwrap().digits == "123456" {
        "654321"
    } else {
        "123456"
    };
    let forged = to_cbor(&SasVerify {
        msg_type: SAS_CONFIRM,
        sas_mac: sas_mac(&peer.bs, wrong).to_vec(),
        nonce: vec![7; 16],
    });
    peer.send(MSG_TYPE_HANDSHAKE, &forged);
    let mut removed = false;
    app.wait_seeing("the pairing to fail", 20, is_failed, |e| {
        removed |= matches!(e, AppEvent::ContactRemoved { peer_id: p } if *p == peer_id)
    })
    .await;
    assert!(removed);
    assert!(app.handle.snapshot().await.unwrap().contacts.is_empty());
    // All state is erased: the user's confirmation has nothing left to confirm.
    assert!(app.handle.confirm_sas(&peer_id).await.is_err());

    // The user rejecting the code ends it the same way.
    let mut app = App::start_with(&relay, |cfg| cfg.request_sas = true).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    let peer_id = peer.id.peer_id.clone();
    peer.send_bootstrap();
    peer.complete_pairing().await;
    app.wait("the SAS to display", 20, |e| {
        matches!(e, AppEvent::SasVerification { .. })
    })
    .await;
    app.handle.reject_sas(&peer_id);
    app.wait("the pairing to fail", 20, is_failed).await;
    assert!(app.handle.snapshot().await.unwrap().contacts.is_empty());
}

// The SAS the client shows is the spec's value for the keys of this bootstrap.
#[clause("PNP-003-MUST-025")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_clients_sas_is_the_spec_value_for_this_bootstrap() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start_with(&relay, |cfg| cfg.request_sas = true).await;
    let (mut peer, seed, first) = RawPeer::presented(&relay, &app).await;
    let init: BootstrapHandshake = from_cbor(&first.plaintext);
    assert!(init.sas, "the app asked for SAS verification");
    // Our answer, of which we keep the ephemeral key.
    let (pairing, outputs) = Pairing::respond(
        &peer.id.keypair(),
        &BootstrapKey::Seed(&seed),
        &first.plaintext,
        Some(&peer.app_ik),
        &mut peer.nonces,
        false,
        now_secs() * 1000,
    )
    .unwrap();
    let resp: BootstrapHandshake = outputs
        .iter()
        .find_map(|o| match o {
            PairingOutput::Send(m) => Some(from_cbor(m)),
            _ => None,
        })
        .unwrap();
    peer.pairing = Some(pairing);
    peer.apply(outputs);
    let ev = app
        .wait("the SAS to display", 20, |e| {
            matches!(e, AppEvent::SasVerification { .. })
        })
        .await;
    let AppEvent::SasVerification { digits, .. } = ev else {
        unreachable!()
    };
    // We presented the code: we are Alice, the app is Bob.
    let expected = compute_sas(
        &peer.bs,
        &peer.id.public,
        &peer.app_ik,
        &resp.ek.clone().try_into().unwrap(),
        &init.ek.clone().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(digits, expected);
}

// -- §7.3: who gets to see the identity key -------------------------------------------------------

#[clause("PNP-003-MUST-047")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bootstrap_handshake_goes_to_the_pairing_peer_only() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    // An existing contact with an open, verified channel.
    let mut contact = pair_as_scanner(&relay, &mut app).await;
    contact.receive(Duration::from_millis(500), |_| false).await;

    // The app scans a code of ours and pairs.
    let (mut peer, seed, first) = RawPeer::presented(&relay, &app).await;
    peer.respond(&seed, &first.plaintext, false);
    loop {
        let d = peer.next_envelope(Duration::from_secs(20)).await.unwrap();
        if d.msg_type == MSG_TYPE_HANDSHAKE {
            assert_eq!(message_type(&d.plaintext), Some(HANDSHAKE_INIT));
            peer.on_handshake(&d.plaintext);
            break;
        }
    }
    peer.expect_first_message().await;
    app.wait("the pairing to complete", 20, is_complete).await;

    // The other contact received nothing while that happened: no handshake message, no
    // announcement of the new contact.
    let leaked = contact.receive(Duration::from_secs(2), |_| false).await;
    assert!(
        leaked.is_empty(),
        "the existing contact was sent {:?}",
        leaked.iter().map(|d| d.msg_type).collect::<Vec<_>>()
    );
    // What crossed the relay towards the new peer (the app's connection offer) names
    // neither identity key nor anything of the code.
    let app_ik_hex = app.handle.public_key().to_owned();
    for needle in [
        app_ik_hex.as_str(),
        &app_ik_hex.to_uppercase(),
        &hex::encode(peer.id.public),
        &hex::encode(seed),
    ] {
        assert!(!peer.remote_sdp.contains(needle));
    }
    // And the relay, at its default log level, recorded neither identity key.
    let log = relay.log().to_lowercase();
    for needle in [app_ik_hex.as_str(), &hex::encode(peer.id.public)] {
        assert!(!log.contains(needle), "the relay logged an identity key");
    }
}

// -- §7.4: no breadcrumbs ---------------------------------------------------------------------------

#[clause("PNP-003-MUST-052")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_leaves_no_log_or_record_of_the_bootstrap() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let before: std::collections::BTreeSet<String> = file_names(&app.data_dir());
    let code = app.handle.create_pairing_code().await.unwrap();
    let seed = parse_qr_text(&code).unwrap().seed.clone();
    let peer = pair_as_scanner(&relay, &mut app).await;
    let peer_id = peer.id.peer_id.clone();
    app.handle.send_text(&peer_id, "saved").await.unwrap();
    app.handle.shutdown().await;

    // Stored persistently: the encrypted store and its key, as before the pairing. No log,
    // no analytics file, nothing new.
    let after = file_names(&app.data_dir());
    let new: Vec<&String> = after.difference(&before).collect();
    assert!(
        new.iter().all(|name| name.starts_with("store.db")),
        "the pairing left new files: {new:?}"
    );
    // No file holds the code, its seed or a bootstrap event in the clear.
    for name in &after {
        // SQLite's `-wal` and `-shm` files go when the store finishes closing, which can be
        // a moment after `shutdown` returns: a file that is gone holds nothing.
        let Ok(bytes) = std::fs::read(app.data_dir().join(name)) else {
            continue;
        };
        let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(code.as_bytes()), "{name} holds the pairing code");
        assert!(!contains(&seed), "{name} holds the seed");
        for word in ["bootstrap", "pairing", "Pairing", "handshake"] {
            assert!(!contains(word.as_bytes()), "{name} mentions {word:?}");
        }
    }
    // Transmitted: the relay is the only third party the client talks to. Nothing of the
    // code reached its log, and it wrote no line about a pairing.
    let log = relay.log();
    assert!(!log.contains(&code) && !log.to_lowercase().contains(&hex::encode(&seed)));
    for needle in ["pairing", "paired", "pair_with"] {
        assert!(
            !log.to_lowercase().contains(needle),
            "the relay logged {needle:?}"
        );
    }
}

fn file_names(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

// -- §7.6: relay hints ------------------------------------------------------------------------------

#[clause("PNP-003-SHOULD-008")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successive_codes_rotate_the_relay_hint() {
    let relay = Relay::start(&[]).await;
    let hints = ["one.example:443", "two.example:443", "three.example:443"];
    let app = App::start_with(&relay, |cfg| {
        cfg.relay_hints = hints.iter().map(|h| h.to_string()).collect();
    })
    .await;
    let mut seen = Vec::new();
    for _ in 0..6 {
        let code = app.handle.create_pairing_code().await.unwrap();
        let payload = parse_qr_text(&code).unwrap();
        assert_eq!(payload.net, bootstrap::NET_INTERNET_RELAY);
        seen.push(payload.relay.clone().expect("a relay hint"));
    }
    // No two codes in a row name the same relay, and every relay takes its turn.
    assert!(seen.windows(2).all(|w| w[0] != w[1]), "{seen:?}");
    for hint in hints {
        assert_eq!(seen.iter().filter(|s| *s == hint).count(), 2, "{seen:?}");
    }

    // With no relay to name, a code carries none.
    let app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    assert_eq!(parse_qr_text(&code).unwrap().relay, None);
}

// -- §5.1 step 3: the QR code itself -----------------------------------------------------------------

/// The error correction level a QR code declares in its format information (ISO/IEC 18004
/// §7.9): 15 bits next to the top-left finder pattern, masked with 0x5412, a BCH(15,5) code
/// word whose two leading bits are the level (01 = L, 00 = M, 11 = Q, 10 = H).
fn declared_ec_level(qr: &parolnet_app::qr::QrMatrix) -> &'static str {
    // The first copy, from its most significant bit: row 8 from the left edge (skipping the
    // timing column), then column 8 upwards (skipping the timing row).
    let cells: [(usize, usize); 15] = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ];
    let bits = cells.iter().fold(0u32, |acc, &(row, col)| {
        (acc << 1) | u32::from(qr.is_dark(row, col))
    });
    let word = bits ^ 0x5412;
    // A valid code word leaves no remainder when divided by the generator 0x537.
    let mut rem = word;
    for shift in (0..5).rev() {
        if rem & (1 << (shift + 10)) != 0 {
            rem ^= 0x537 << shift;
        }
    }
    assert_eq!(
        rem, 0,
        "the format information was read wrongly: {bits:015b}"
    );
    match word >> 13 {
        0b01 => "L",
        0b00 => "M",
        0b11 => "Q",
        _ => "H",
    }
}

#[clause("PNP-003-MUST-008")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pairing_qr_code_has_error_correction_level_m() {
    let relay = Relay::start(&[]).await;
    let app = App::start_with(&relay, |cfg| {
        cfg.relay_hints = vec!["relay.example:443".into()];
    })
    .await;
    for _ in 0..3 {
        let code = app.handle.create_pairing_code().await.unwrap();
        let qr = parolnet_app::qr::pairing_qr(&code).expect("the code fits a QR code");
        assert_eq!(qr.dark.len(), qr.width * qr.width);
        assert_eq!(declared_ec_level(&qr), "M");
        // Base45 is drawn in alphanumeric mode: a code of about 260 characters fits version
        // 10 (57 modules) at level M, where byte mode would need version 12.
        assert!(
            qr.width <= 57,
            "{} modules for {} characters",
            qr.width,
            code.len()
        );
    }
    // The reader of the format information tells the levels apart.
    for (level, name) in [
        (qrcode::EcLevel::L, "L"),
        (qrcode::EcLevel::M, "M"),
        (qrcode::EcLevel::Q, "Q"),
        (qrcode::EcLevel::H, "H"),
    ] {
        let reference = qrcode::QrCode::with_error_correction_level(b"PNP-003", level).unwrap();
        let matrix = parolnet_app::qr::QrMatrix {
            width: reference.width(),
            dark: reference
                .to_colors()
                .into_iter()
                .map(|c| c == qrcode::Color::Dark)
                .collect(),
        };
        assert_eq!(declared_ec_level(&matrix), name);
    }
}

// -- §6.1 (c), §6.3: SAS verification is what a pairing does unless told otherwise ----------------------

#[clause("PNP-003-SHOULD-004", "PNP-003-SHOULD-006")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_asks_for_sas_verification_unless_configured_not_to() {
    use parolnet_app::AppConfig;
    // The configuration a client starts from asks for it.
    assert!(AppConfig::new("unused", "ws://127.0.0.1:1/ws").request_sas);

    // So a client started with it draws a peer that did not ask into the verification: its
    // BootstrapHandshake says so, both sides end up in SAS_PENDING and nothing completes
    // until the users have compared the code.
    let relay = Relay::start(&[]).await;
    let mut app = App::start_with(&relay, |cfg| {
        cfg.request_sas = AppConfig::new("unused", "ws://127.0.0.1:1/ws").request_sas;
    })
    .await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    peer.send_bootstrap();
    let d = peer.next_envelope(Duration::from_secs(20)).await.unwrap();
    let resp: BootstrapHandshake = from_cbor(&d.plaintext);
    assert!(resp.sas, "the client did not ask for SAS verification");
    peer.on_handshake(&d.plaintext);
    assert_eq!(
        peer.pairing.as_ref().unwrap().state(),
        PairingState::SasPending
    );
    app.wait("the SAS to display", 20, |e| {
        matches!(e, AppEvent::SasVerification { .. })
    })
    .await;
    let events = app.drain(Duration::from_secs(2)).await;
    assert!(!events.iter().any(is_complete));
}
