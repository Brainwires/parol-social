//! Pairing (PNP-003) for the web app: the bindings over `parolnet_core::bootstrap`.
//!
//! The protocol lives once, in the core: the QR payload and its base45 text, the passphrase
//! alternative, the BootstrapHandshake / SASVerify state machine
//! ([`parolnet_core::bootstrap::pairing::Pairing`]) and the hand-over to the PNP-002 session.
//! These exports keep one [`Pairing`] per peer in wasm memory and hand JavaScript only what it
//! has to carry or show:
//!
//! - a **code** to display ([`pairing_create_code`]) and the presenter's pending half of it
//!   (`export_pending_bootstrap` and friends in the crate root);
//! - **steps** to carry out in order after each call (see [`Step`]): a handshake message to
//!   send as a `HANDSHAKE` (0x05) envelope, a SAS to show, the PNP-002 session to install
//!   ([`pairing_install_session`]) and the end of the pairing.
//!
//! No secret crosses the boundary: seeds, Bootstrap Secrets, pre-keys and sessions stay here,
//! and are erased when a pairing ends either way.
//!
//! The bodies (`*_in`) take the state and return plain values so they run in native tests;
//! the `#[wasm_bindgen]` wrappers only convert.

use std::collections::HashMap;

use parolnet_core::bootstrap::pairing::{
    BootstrapKey, MSG_TYPE_HANDSHAKE, Pairing, PairingError, PairingOutput, PairingState,
};
use parolnet_core::bootstrap::passphrase::{self, PassphrasePayload, StretchedPassphrase};
use parolnet_core::bootstrap::{self, NonceTracker, QrPayload};
use parolnet_core::envelope::try_bootstrap_and_decrypt_from;
use parolnet_crypto::IdentityKeyPair;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_protocol::address::PeerId;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{NOT_INITIALIZED, STATE, WasmState};

/// The code is older than a scanner may accept (PNP-003-MUST-011).
pub(crate) const ERR_CODE_EXPIRED: &str = "code-expired";
/// The text is not a pairing code this version can use.
pub(crate) const ERR_CODE_INVALID: &str = "code-invalid";
/// The code is this device's own.
pub(crate) const ERR_OWN_CODE: &str = "own-code";
/// No pairing with that peer is under way.
pub(crate) const ERR_NO_PAIRING: &str = "no-pairing";
/// The call does not apply to the pairing's state (nothing changed).
pub(crate) const ERR_WRONG_STATE: &str = "wrong-state";

/// The pairings under way, in wasm memory only: none survives a reload.
#[derive(Default)]
pub(crate) struct Pairings {
    /// One bootstrap per peer (keyed by PeerId).
    open: HashMap<[u8; 32], Pairing>,
    /// PNP-002 sessions a pairing produced, until the caller installs them.
    staged: HashMap<[u8; 32], Box<DoubleRatchetSession>>,
    /// Handshake nonces of the last 60 minutes (PNP-003-MUST-043).
    nonces: NonceTracker,
    /// The stretched passphrase this device issued, until a peer bootstraps with it.
    passphrase: Option<StretchedPassphrase>,
}

impl Pairings {
    /// Abort every pairing and erase what it held.
    pub(crate) fn clear(&mut self) {
        for pairing in self.open.values_mut() {
            pairing.abort();
        }
        self.open.clear();
        self.staged.clear();
        self.passphrase = None;
        self.nonces = NonceTracker::default();
    }
}

/// What the caller does next, in order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Step {
    /// Send this handshake message (hex) to the peer: the payload of a `HANDSHAKE` (0x05)
    /// envelope of the session held with it now.
    Send { payload_hex: String },
    /// Show this SAS and ask the user whether the peer shows the same
    /// (PNP-003-MUST-026, -MUST-027).
    Sas { digits: String, emoji: String },
    /// The PNP-002 session is ready: once every `Send` before this step has been encrypted,
    /// call `pairing_install_session`. It replaces the bootstrap session.
    Session,
    /// The pairing is over and its secrets are erased. An initiator sends the session's
    /// first message now (PNP-002-MUST-021).
    Established { sas_verified: bool },
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Code {
    /// What the QR code shows: base45 of the CBOR payload (PNP-003-MUST-007).
    code: String,
    /// The same code in the form to copy as text (no blanks).
    text: String,
    /// The payload's `ts` (seconds, floored to 5 minutes).
    ts: u64,
    /// When a scanner stops accepting it (seconds): `ts` plus 30 minutes.
    expires_secs: u64,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Initiated {
    peer_id: String,
    identity_key: String,
    /// The BOOTSTRAP_INIT to send first (hex). In the QR flow it goes in the
    /// bootstrap-completing envelope, with our identity key as `source_hint`.
    init_hex: String,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Responded {
    /// False: the code is spent and the bootstrap was aborted (`reason`); nothing is kept.
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    steps: Vec<Step>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct IssuedPassphrase {
    /// The words to tell the contact out of band (PNP-003-MUST-014). Never sent anywhere.
    phrase: String,
    words: usize,
    /// To be shown to the user (PNP-003-MUST-019).
    entropy_bits: u32,
    /// The words with this device's identity key, as one line of text (§3.2).
    payload: String,
}

/// Why a pairing was aborted, in words a caller can switch on.
fn reason(e: &PairingError) -> &'static str {
    match e {
        PairingError::ProofFailed => "proof-failed",
        PairingError::Replay => "replay",
        PairingError::SasMismatch => "sas-mismatch",
        PairingError::SasRejected => "sas-rejected",
        PairingError::Timeout => "timeout",
        PairingError::WrongState => ERR_WRONG_STATE,
        PairingError::Malformed | PairingError::BadPreKeyBundle | PairingError::Handshake(_) => {
            "failed"
        }
    }
}

fn identity(client: &parolnet_core::ParolNet) -> IdentityKeyPair {
    let mut secret = client.export_identity_secret();
    let identity = IdentityKeyPair::from_secret_bytes(&secret);
    secret.zeroize();
    identity
}

/// Turn a pairing's outputs into steps: a session is staged, an ended pairing is forgotten.
fn steps(pairings: &mut Pairings, peer: [u8; 32], outputs: Vec<PairingOutput>) -> Vec<Step> {
    outputs
        .into_iter()
        .map(|output| match output {
            PairingOutput::Send(payload) => Step::Send {
                payload_hex: hex::encode(payload),
            },
            PairingOutput::ShowSas(sas) => Step::Sas {
                digits: sas.digits,
                emoji: sas.emoji.iter().collect(),
            },
            PairingOutput::Session(session) => {
                pairings.staged.insert(peer, session);
                Step::Session
            }
            PairingOutput::Established { sas_verified } => {
                pairings.open.remove(&peer);
                Step::Established { sas_verified }
            }
        })
        .collect()
}

/// Put `pairing` in the place of whatever was under way with `peer`.
fn replace(pairings: &mut Pairings, peer: [u8; 32], pairing: Pairing) {
    if let Some(mut old) = pairings.open.insert(peer, pairing) {
        old.abort();
    }
    pairings.staged.remove(&peer);
}

pub(crate) fn create_code_in(
    state: &mut WasmState,
    relay_hint: Option<&str>,
) -> Result<Code, String> {
    let client = state.client.as_ref().ok_or(NOT_INITIALIZED)?;
    let result = bootstrap::generate_qr_payload_with_ratchet(&client.public_key(), relay_hint)
        .map_err(|e| e.to_string())?;
    // `QrPayload` erases its copy of the seed when dropped.
    let ts = ciborium::from_reader::<QrPayload, _>(&result.payload_bytes[..])
        .map_err(|e| e.to_string())?
        .ts;
    state.pending_bootstrap = Some(crate::PendingBootstrap {
        seed: result.seed,
        ratchet_secret: result.ratchet_secret,
    });
    Ok(Code {
        code: result.text.clone(),
        text: bootstrap::qr_text_for_copying(&result.text),
        ts,
        expires_secs: ts + bootstrap::QR_MAX_AGE_SECS,
    })
}

/// A scanned or pasted code, validated as of `now_secs` (PNP-003-MUST-010, -MUST-011).
fn parse_code(text: &str, now_secs: u64) -> Result<QrPayload, &'static str> {
    let cbor = Zeroizing::new(bootstrap::decode_qr_text(text).map_err(|_| ERR_CODE_INVALID)?);
    match bootstrap::parse_qr_payload_at(&cbor, now_secs) {
        Ok(payload) => Ok(payload),
        Err(_) => {
            // Well-formed but too old, or not a code at all?
            let ts = ciborium::from_reader::<QrPayload, _>(&cbor[..])
                .map_err(|_| ERR_CODE_INVALID)?
                .ts;
            let well_formed = bootstrap::parse_qr_payload_at(&cbor, ts).is_ok();
            if well_formed && now_secs.saturating_sub(ts) > bootstrap::QR_MAX_AGE_SECS {
                Err(ERR_CODE_EXPIRED)
            } else {
                Err(ERR_CODE_INVALID)
            }
        }
    }
}

/// The scanner's side (§5.1 steps 5 to 7, §5.4 step 1): validate the code, derive the
/// Bootstrap Secret, set up the bootstrap session of PNP-001 §5.3.1 and start the pairing.
pub(crate) fn initiate_in(
    state: &mut WasmState,
    text: &str,
    request_sas: bool,
    now_ms: u64,
) -> Result<Initiated, String> {
    let client = state.client.as_ref().ok_or(NOT_INITIALIZED)?;
    let our_ik = client.public_key();
    let payload = parse_code(text, now_ms / 1000)?;
    let invalid = || ERR_CODE_INVALID.to_owned();
    let their_ik: [u8; 32] = payload.ik.as_slice().try_into().map_err(|_| invalid())?;
    if their_ik == our_ik {
        return Err(ERR_OWN_CODE.into());
    }
    // Without a ratchet key there is no bootstrap session to carry the handshake.
    let ratchet_key: [u8; 32] = payload.rk.as_slice().try_into().map_err(|_| invalid())?;
    let mut seed: [u8; 32] = payload.seed.as_slice().try_into().map_err(|_| invalid())?;
    let bs = bootstrap::derive_bootstrap_secret(&seed, &our_ik, &their_ik);
    seed.zeroize();
    drop(payload); // erases its copy of the seed
    let mut bs = bs.map_err(|e| e.to_string())?;

    let secret = parolnet_crypto::SharedSecret(bs);
    let started = Pairing::initiate(&identity(client), &mut bs, their_ik, request_sas, now_ms);
    bs.zeroize();
    let (pairing, init) = started.map_err(|e| e.to_string())?;
    let peer = PeerId::from_public_key(&their_ik);
    client
        .establish_session(peer, secret, &ratchet_key, true)
        .map_err(|e| e.to_string())?;
    replace(&mut state.pairings, peer.0, pairing);
    Ok(Initiated {
        peer_id: hex::encode(peer.0),
        identity_key: hex::encode(their_ik),
        init_hex: hex::encode(init),
    })
}

/// The presenter's side of PNP-001 §5.3.1 step 6 and PNP-003 §5.4 steps 3 and 4.
///
/// `envelope` arrived from `expected` (the PeerId at the other end of the connection). `Err`:
/// it is not that peer's bootstrap envelope for the code on display, and nothing changed (the
/// code stays valid, a session already held with that peer is as it was). `Ok`: the code is
/// spent (one bootstrap per seed, PNP-003-MUST-040); what the envelope carried had to be the
/// scanner's BootstrapHandshake with a valid proof (PNP-003-MUST-022), or the bootstrap is
/// aborted (`accepted: false`) and no session is kept.
pub(crate) fn respond_in(
    state: &mut WasmState,
    expected: &PeerId,
    envelope: &[u8],
    request_sas: bool,
    now_ms: u64,
) -> Result<Responded, String> {
    let WasmState {
        client,
        pending_bootstrap,
        pairings,
        ..
    } = state;
    let client = client.as_ref().ok_or(NOT_INITIALIZED)?;
    let pending = pending_bootstrap.take().ok_or("no pending bootstrap")?;
    let decrypted = try_bootstrap_and_decrypt_from(
        client.sessions(),
        envelope,
        expected,
        &client.public_key(),
        &pending.seed,
        &pending.ratchet_secret,
    );
    let (ik, decoded) = match decrypted {
        Ok(found) => found,
        Err(e) => {
            *pending_bootstrap = Some(pending);
            return Err(e.to_string());
        }
    };
    let responded = if decoded.msg_type == MSG_TYPE_HANDSHAKE {
        Pairing::respond(
            &identity(client),
            &BootstrapKey::Seed(&pending.seed),
            &decoded.plaintext,
            Some(&ik),
            &mut pairings.nonces,
            request_sas,
            now_ms,
        )
        .map_err(|e| reason(&e))
    } else {
        Err("failed")
    };
    drop(pending); // seed and ratchet secret are erased
    match responded {
        Ok((pairing, outputs)) => {
            replace(pairings, expected.0, pairing);
            Ok(Responded {
                accepted: true,
                identity_key: Some(hex::encode(ik)),
                reason: None,
                steps: steps(pairings, expected.0, outputs),
            })
        }
        Err(reason) => {
            client.sessions().remove_session(expected);
            if let Some(mut old) = pairings.open.remove(&expected.0) {
                old.abort();
            }
            pairings.staged.remove(&expected.0);
            Ok(Responded {
                accepted: false,
                identity_key: None,
                reason: Some(reason),
                steps: Vec::new(),
            })
        }
    }
}

/// Abort the pairing with `peer`, if one is under way (§4: back to NO_CONTACT): its secrets
/// are erased and the session it was using is removed. True when there was one.
pub(crate) fn abort_in(state: &mut WasmState, peer: &[u8; 32]) -> bool {
    let open = state.pairings.open.remove(peer).map(|mut p| p.abort());
    let staged = state.pairings.staged.remove(peer);
    let had = open.is_some() || staged.is_some();
    if had && let Some(client) = state.client.as_ref() {
        client.sessions().remove_session(&PeerId(*peer));
    }
    had
}

/// A handshake message from the peer. `Err` is the reason the pairing was aborted (it is gone,
/// with its session), or [`ERR_NO_PAIRING`].
pub(crate) fn on_message_in(
    state: &mut WasmState,
    peer: &[u8; 32],
    payload: &[u8],
    now_ms: u64,
) -> Result<Vec<Step>, String> {
    let Pairings { open, nonces, .. } = &mut state.pairings;
    let pairing = open.get_mut(peer).ok_or(ERR_NO_PAIRING)?;
    match pairing.on_message(payload, nonces, now_ms) {
        Ok(outputs) => Ok(steps(&mut state.pairings, *peer, outputs)),
        Err(e) => {
            abort_in(state, peer);
            Err(reason(&e).into())
        }
    }
}

/// The first message of the PNP-002 session arrived and decrypted: a responder's pairing is
/// ESTABLISHED. No steps when that is not what the pairing was waiting for.
pub(crate) fn first_message_in(state: &mut WasmState, peer: &[u8; 32]) -> Vec<Step> {
    let Some(pairing) = state.pairings.open.get_mut(peer) else {
        return Vec::new();
    };
    let outputs = pairing.on_first_message();
    steps(&mut state.pairings, *peer, outputs)
}

/// The user confirms the SAS (PNP-003-MUST-028). `Err(ERR_WRONG_STATE)`: no SAS is waiting
/// for this user (nothing changed); any other error: the pairing was aborted.
pub(crate) fn confirm_sas_in(
    state: &mut WasmState,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<Step>, String> {
    let pairing = state.pairings.open.get_mut(peer).ok_or(ERR_NO_PAIRING)?;
    match pairing.confirm_sas(now_ms) {
        Ok(outputs) => Ok(steps(&mut state.pairings, *peer, outputs)),
        Err(e) => {
            if pairing.state() == PairingState::Aborted {
                abort_in(state, peer);
            }
            Err(reason(&e).into())
        }
    }
}

/// Make the staged PNP-002 session the one held with `peer`.
pub(crate) fn install_session_in(state: &mut WasmState, peer: &[u8; 32]) -> Result<(), String> {
    let client = state.client.as_ref().ok_or(NOT_INITIALIZED)?;
    let session = state.pairings.staged.remove(peer).ok_or(ERR_NO_PAIRING)?;
    client.sessions().add_session(PeerId(*peer), *session);
    Ok(())
}

/// Enforce the timeouts of §4 and of the PNP-002 handshake: the peers whose pairing just
/// timed out (each is aborted and gone).
pub(crate) fn timeouts_in(state: &mut WasmState, now_ms: u64) -> Vec<[u8; 32]> {
    let timed_out: Vec<[u8; 32]> = state
        .pairings
        .open
        .iter_mut()
        .filter_map(|(peer, pairing)| pairing.check_timeout(now_ms).err().map(|_| *peer))
        .collect();
    for peer in &timed_out {
        abort_in(state, peer);
    }
    timed_out
}

pub(crate) fn state_in(state: &WasmState, peer: &[u8; 32]) -> Option<&'static str> {
    state.pairings.open.get(peer).map(|p| match p.state() {
        PairingState::SecretShared => "secret_shared",
        PairingState::SasPending => "sas_pending",
        PairingState::Handshaking => "handshaking",
        PairingState::Accepted => "accepted",
        PairingState::Established => "established",
        PairingState::Aborted => "aborted",
    })
}

/// Issue a passphrase (§5.3): 8 words, their entropy, and the payload to pass on with them.
/// The stretched passphrase is kept until a peer bootstraps with it or it is cleared.
pub(crate) fn passphrase_issue_in(state: &mut WasmState) -> Result<IssuedPassphrase, String> {
    let client = state.client.as_ref().ok_or(NOT_INITIALIZED)?;
    let generated = passphrase::generate();
    let payload = PassphrasePayload::new(&client.public_key(), &generated.phrase)
        .and_then(|p| p.to_text())
        .map_err(|e| e.to_string())?;
    let mut copy = generated.phrase.to_string();
    let stretched = StretchedPassphrase::stretch(&mut copy).map_err(|e| e.to_string())?;
    state.pairings.passphrase = Some(stretched);
    Ok(IssuedPassphrase {
        phrase: generated.phrase.to_string(),
        words: generated.words,
        entropy_bits: generated.entropy_bits,
        payload: bootstrap::qr_text_for_copying(&payload),
    })
}

/// The side that was told a passphrase (§5.2): derive the Bootstrap Secret and start the
/// pairing. There is no bootstrap session in this flow: the caller carries the messages.
pub(crate) fn initiate_passphrase_in(
    state: &mut WasmState,
    payload_text: &str,
    request_sas: bool,
    now_ms: u64,
) -> Result<Initiated, String> {
    let client = state.client.as_ref().ok_or(NOT_INITIALIZED)?;
    let our_ik = client.public_key();
    let mut payload =
        PassphrasePayload::from_text(payload_text).map_err(|_| ERR_CODE_INVALID.to_owned())?;
    let their_ik = payload.identity_key();
    if their_ik == our_ik {
        return Err(ERR_OWN_CODE.into());
    }
    // Erases the passphrase (PNP-003-MUST-016).
    let mut bs = passphrase::derive_bootstrap_secret(&mut payload.phrase, &our_ik, &their_ik)
        .map_err(|e| e.to_string())?;
    let started = Pairing::initiate(&identity(client), &mut bs, their_ik, request_sas, now_ms);
    bs.zeroize();
    let (pairing, init) = started.map_err(|e| e.to_string())?;
    let peer = PeerId::from_public_key(&their_ik);
    replace(&mut state.pairings, peer.0, pairing);
    Ok(Initiated {
        peer_id: hex::encode(peer.0),
        identity_key: hex::encode(their_ik),
        init_hex: hex::encode(init),
    })
}

/// The issuer's answer to a BOOTSTRAP_INIT made from its passphrase. `Err`: the proof did not
/// verify (or no passphrase is pending) and the passphrase stays valid. `Ok`: the passphrase
/// is spent.
pub(crate) fn respond_passphrase_in(
    state: &mut WasmState,
    init: &[u8],
    request_sas: bool,
    now_ms: u64,
) -> Result<Responded, String> {
    let WasmState {
        client, pairings, ..
    } = state;
    let client = client.as_ref().ok_or(NOT_INITIALIZED)?;
    let stretched = pairings
        .passphrase
        .as_ref()
        .ok_or("no pending passphrase")?;
    let (pairing, outputs) = Pairing::respond(
        &identity(client),
        &BootstrapKey::Passphrase(stretched),
        init,
        None,
        &mut pairings.nonces,
        request_sas,
        now_ms,
    )
    .map_err(|e| reason(&e).to_owned())?;
    pairings.passphrase = None; // erased
    let their_ik = pairing.peer_identity_key();
    let peer = PeerId::from_public_key(&their_ik);
    replace(pairings, peer.0, pairing);
    Ok(Responded {
        accepted: true,
        identity_key: Some(hex::encode(their_ik)),
        reason: None,
        steps: steps(pairings, peer.0, outputs),
    })
}

// ── Exports ─────────────────────────────────────────────────

fn lock() -> std::sync::MutexGuard<'static, WasmState> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

fn err(message: String) -> JsError {
    JsError::new(&message)
}

fn peer_id(peer_id_hex: &str) -> Result<[u8; 32], JsError> {
    crate::try_decode_32(peer_id_hex).map_err(|()| JsError::new("a peer id is 32 bytes of hex"))
}

fn bytes(hex_str: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(hex_str).map_err(|e| JsError::new(&format!("invalid hex: {e}")))
}

/// Make a pairing code and keep its pending half (seed and ratchet secret) in wasm memory,
/// replacing an earlier one. Returns `{ code, text, ts, expires_secs }`: `code` is what the QR
/// code shows (base45, PNP-003-MUST-007), `text` the same code for copying as text.
#[wasm_bindgen]
pub fn pairing_create_code(relay_hint: Option<String>) -> Result<JsValue, JsError> {
    js(&create_code_in(&mut lock(), relay_hint.as_deref()).map_err(err)?)
}

/// Pair with a scanned or pasted code (either form). Throws `code-invalid`, `code-expired` or
/// `own-code`; otherwise the bootstrap session with the presenter exists and the result is
/// `{ peer_id, identity_key, init_hex }`: send `init_hex` as the first `HANDSHAKE` envelope,
/// with this device's identity key as `source_hint` (PNP-001-MUST-063).
#[wasm_bindgen]
pub fn pairing_initiate(text: &str, request_sas: bool, now_ms: f64) -> Result<JsValue, JsError> {
    js(&initiate_in(&mut lock(), text, request_sas, now_ms as u64).map_err(err)?)
}

/// The presenter's answer to the scanner's bootstrap envelope. Throws when the envelope is
/// not `expected_peer_id_hex`'s bootstrap for the code on display (nothing changed). Otherwise
/// the code is spent: `{ accepted: true, identity_key, steps }`, or `{ accepted: false,
/// reason, steps: [] }` when the bootstrap was aborted.
#[wasm_bindgen]
pub fn pairing_respond(
    expected_peer_id_hex: &str,
    envelope_hex: &str,
    request_sas: bool,
    now_ms: f64,
) -> Result<JsValue, JsError> {
    let expected = PeerId(peer_id(expected_peer_id_hex)?);
    let envelope = bytes(envelope_hex)?;
    js(&respond_in(
        &mut lock(),
        &expected,
        &envelope,
        request_sas,
        now_ms as u64,
    )
    .map_err(err)?)
}

/// A handshake message (the plaintext of a `HANDSHAKE` envelope, hex) from a peer a pairing
/// is under way with. Returns the steps to take; throws the reason when the pairing was
/// aborted (it is gone, and so is its session).
#[wasm_bindgen]
pub fn pairing_on_message(
    peer_id_hex: &str,
    payload_hex: &str,
    now_ms: f64,
) -> Result<JsValue, JsError> {
    let peer = peer_id(peer_id_hex)?;
    let payload = bytes(payload_hex)?;
    js(&on_message_in(&mut lock(), &peer, &payload, now_ms as u64).map_err(err)?)
}

/// An envelope of the session with this peer decrypted: if its pairing was waiting for the
/// PNP-002 session's first message, it is ESTABLISHED. Returns the steps (often none).
#[wasm_bindgen]
pub fn pairing_first_message(peer_id_hex: &str) -> Result<JsValue, JsError> {
    js(&first_message_in(&mut lock(), &peer_id(peer_id_hex)?))
}

/// The user says the SAS matches. Throws `wrong-state` when no SAS is waiting for the user
/// (nothing changed), another reason when the pairing was aborted.
#[wasm_bindgen]
pub fn pairing_confirm_sas(peer_id_hex: &str, now_ms: f64) -> Result<JsValue, JsError> {
    js(&confirm_sas_in(&mut lock(), &peer_id(peer_id_hex)?, now_ms as u64).map_err(err)?)
}

/// Carry out a `session` step: the PNP-002 session replaces the bootstrap session.
#[wasm_bindgen]
pub fn pairing_install_session(peer_id_hex: &str) -> Result<(), JsError> {
    install_session_in(&mut lock(), &peer_id(peer_id_hex)?).map_err(err)
}

/// Abort the pairing with a peer (the user rejected the SAS, the connection was lost): its
/// secrets are erased and its session is removed. True when one was under way.
#[wasm_bindgen]
pub fn pairing_abort(peer_id_hex: &str) -> Result<bool, JsError> {
    Ok(abort_in(&mut lock(), &peer_id(peer_id_hex)?))
}

/// The peers (hex) whose pairing just timed out; each is aborted as by [`pairing_abort`].
#[wasm_bindgen]
pub fn pairing_timeouts(now_ms: f64) -> Vec<String> {
    timeouts_in(&mut lock(), now_ms as u64)
        .iter()
        .map(hex::encode)
        .collect()
}

/// Where the pairing with a peer stands (`secret_shared`, `sas_pending`, `handshaking`,
/// `accepted`), or `undefined` when none is under way.
#[wasm_bindgen]
pub fn pairing_state(peer_id_hex: &str) -> Option<String> {
    let peer = crate::try_decode_32(peer_id_hex).ok()?;
    state_in(&lock(), &peer).map(str::to_owned)
}

/// Issue a passphrase to pair with (PNP-003 §5.2, §5.3): `{ phrase, words, entropy_bits,
/// payload }`. The words are told to the contact out of band and never sent over the network
/// (PNP-003-MUST-004, -MUST-014). Takes a moment (Argon2id over 64 MiB).
#[wasm_bindgen]
pub fn passphrase_issue() -> Result<JsValue, JsError> {
    js(&passphrase_issue_in(&mut lock()).map_err(err)?)
}

/// How many words `phrase` has. Throws when it is not an acceptable passphrase (fewer than 6
/// words, or a word that is not on the list; PNP-003-MUST-013, -MUST-041).
#[wasm_bindgen]
pub fn passphrase_validate(phrase: &str) -> Result<u32, JsError> {
    passphrase::validate(phrase)
        .map(|words| words as u32)
        .map_err(|e| err(e.to_string()))
}

/// Forget the passphrase this device issued (its stretched form is erased).
#[wasm_bindgen]
pub fn passphrase_clear() {
    lock().pairings.passphrase = None;
}

/// Start a pairing from a contact's passphrase payload. As [`pairing_initiate`], without a
/// bootstrap session: the caller carries `init_hex` and what follows to the issuer.
#[wasm_bindgen]
pub fn pairing_initiate_passphrase(
    payload_text: &str,
    request_sas: bool,
    now_ms: f64,
) -> Result<JsValue, JsError> {
    js(
        &initiate_passphrase_in(&mut lock(), payload_text, request_sas, now_ms as u64)
            .map_err(err)?,
    )
}

/// The issuer's answer to a BOOTSTRAP_INIT (hex) made from its passphrase. Throws when the
/// proof does not verify (the passphrase stays valid); otherwise as [`pairing_respond`].
#[wasm_bindgen]
pub fn pairing_respond_passphrase(
    init_hex: &str,
    request_sas: bool,
    now_ms: f64,
) -> Result<JsValue, JsError> {
    let init = bytes(init_hex)?;
    js(&respond_passphrase_in(&mut lock(), &init, request_sas, now_ms as u64).map_err(err)?)
}

// A whole pairing through the bodies above, against a peer that runs the core's `Pairing`
// directly. They share `STATE` with the crate's other tests, hence `#[serial]`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clear_pending_bootstrap, envelope_encode, export_pending_bootstrap, export_secret_key,
        get_public_key, has_session, import_pending_bootstrap, initialize, initialize_from_key,
        panic_wipe, try_decode_32,
    };
    use parolnet_core::envelope::{decrypt_for_peer, decrypt_from_envelope, encrypt_into_envelope};
    use serial_test::serial;
    use x25519_dalek::StaticSecret;

    const HANDSHAKE: u8 = MSG_TYPE_HANDSHAKE;
    const CONTROL: u8 = 0x03;
    const TEXT: u8 = 0x01;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn now_secs() -> u64 {
        now_ms() / 1000
    }

    fn state() -> std::sync::MutexGuard<'static, WasmState> {
        lock()
    }

    /// A new identity in the wasm state: its PeerId and identity key.
    fn fresh() -> (PeerId, [u8; 32]) {
        panic_wipe();
        let id = PeerId(try_decode_32(&initialize()).unwrap());
        (id, try_decode_32(&get_public_key()).unwrap())
    }

    /// The other device: the core's own types, no wasm state.
    struct Remote {
        identity: IdentityKeyPair,
        ik: [u8; 32],
        id: PeerId,
        session: Option<DoubleRatchetSession>,
        pairing: Option<Pairing>,
        nonces: NonceTracker,
    }

    impl Remote {
        fn new() -> Remote {
            let identity = IdentityKeyPair::generate();
            let ik = identity.public_key_bytes();
            Remote {
                identity,
                ik,
                id: PeerId::from_public_key(&ik),
                session: None,
                pairing: None,
                nonces: NonceTracker::default(),
            }
        }

        /// Scan a code the wasm side shows: the bootstrap envelope to send it.
        fn scan(&mut self, code: &str, me: &PeerId, request_sas: bool) -> Vec<u8> {
            let qr = bootstrap::parse_qr_text(code).unwrap();
            let seed: [u8; 32] = qr.seed.as_slice().try_into().unwrap();
            let their_ik: [u8; 32] = qr.ik.as_slice().try_into().unwrap();
            let rk: [u8; 32] = qr.rk.as_slice().try_into().unwrap();
            let mut bs = bootstrap::derive_bootstrap_secret(&seed, &self.ik, &their_ik).unwrap();
            self.session = Some(DoubleRatchetSession::initialize_initiator(bs, &rk).unwrap());
            let (pairing, init) =
                Pairing::initiate(&self.identity, &mut bs, their_ik, request_sas, now_ms())
                    .unwrap();
            self.pairing = Some(pairing);
            self.seal(me, HANDSHAKE, &init, true)
        }

        fn seal(&mut self, to: &PeerId, msg_type: u8, body: &[u8], hint: bool) -> Vec<u8> {
            encrypt_into_envelope(
                self.session.as_mut().unwrap(),
                to,
                msg_type,
                body,
                now_secs(),
                hint.then_some(PeerId(self.ik)),
            )
            .unwrap()
        }

        fn open(&mut self, envelope_hex: &str) -> Vec<u8> {
            decrypt_from_envelope(
                self.session.as_mut().unwrap(),
                &hex::decode(envelope_hex).unwrap(),
            )
            .unwrap()
            .plaintext
        }

        fn on_message(&mut self, payload: &[u8]) -> Vec<PairingOutput> {
            self.pairing
                .as_mut()
                .unwrap()
                .on_message(payload, &mut self.nonces, now_ms())
                .unwrap()
        }
    }

    /// Encrypt a step's payload under the session the wasm side holds with `peer` now.
    fn seal_ours(peer: &PeerId, msg_type: u8, payload_hex: &str, hint: Option<String>) -> String {
        envelope_encode(
            &hex::encode(peer.0),
            msg_type,
            &hex::decode(payload_hex).unwrap(),
            now_secs(),
            hint,
        )
        .ok()
        .unwrap()
    }

    fn open_ours(peer: &PeerId, envelope: &[u8]) -> (u8, Vec<u8>) {
        let guard = state();
        let sessions = guard.client.as_ref().unwrap().sessions();
        let decoded = decrypt_for_peer(sessions, peer, envelope).unwrap();
        (decoded.msg_type, decoded.plaintext)
    }

    fn sent(step: &Step) -> &str {
        match step {
            Step::Send { payload_hex } => payload_hex,
            other => panic!("expected a send step, got {other:?}"),
        }
    }

    fn only_send(outputs: Vec<PairingOutput>) -> Vec<u8> {
        let mut outputs = outputs.into_iter();
        match (outputs.next(), outputs.next()) {
            (Some(PairingOutput::Send(payload)), None) => payload,
            _ => panic!("expected exactly one message to send"),
        }
    }

    #[test]
    #[serial]
    fn a_scanner_pairs_with_the_code_on_display_and_both_confirm_the_sas() {
        let (me, _) = fresh();
        let code = create_code_in(&mut state(), None).unwrap();
        assert_eq!(code.expires_secs, code.ts + 1800);
        assert!(!code.text.contains(' '));
        assert_eq!(bootstrap::decode_qr_text(&code.text).unwrap(), {
            bootstrap::decode_qr_text(&code.code).unwrap()
        });
        assert!(export_pending_bootstrap().is_some());

        let mut remote = Remote::new();
        // The scanner does not ask for the SAS; this side does, so both show it.
        let envelope = remote.scan(&code.text, &me, false);
        let responded = respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).unwrap();
        assert!(responded.accepted);
        assert_eq!(responded.identity_key, Some(hex::encode(remote.ik)));
        // The code is spent (PNP-003-MUST-040).
        assert!(export_pending_bootstrap().is_none());
        assert!(has_session(&hex::encode(remote.id.0)));
        assert_eq!(state_in(&state(), &remote.id.0), Some("sas_pending"));
        let [resp, Step::Sas { digits, emoji }] = &responded.steps[..] else {
            panic!(
                "expected BOOTSTRAP_RESP and the SAS, got {:?}",
                responded.steps
            );
        };
        assert_eq!(digits.len(), 6);
        assert_eq!(emoji.chars().count(), 5);

        // The scanner verifies our proof and shows the same SAS.
        let resp = remote.open(&seal_ours(&remote.id, HANDSHAKE, sent(resp), None));
        let outputs = remote.on_message(&resp);
        let [PairingOutput::ShowSas(sas)] = &outputs[..] else {
            panic!("the scanner shows the SAS");
        };
        assert_eq!(&sas.digits, digits);
        assert_eq!(&sas.emoji.iter().collect::<String>(), emoji);

        // Their confirmation arrives first: nothing moves until ours is given.
        let theirs = only_send(
            remote
                .pairing
                .as_mut()
                .unwrap()
                .confirm_sas(now_ms())
                .unwrap(),
        );
        let envelope = remote.seal(&me, HANDSHAKE, &theirs, false);
        let (msg_type, payload) = open_ours(&remote.id, &envelope);
        assert_eq!(msg_type, HANDSHAKE);
        assert!(
            on_message_in(&mut state(), &remote.id.0, &payload, now_ms())
                .unwrap()
                .is_empty()
        );
        let ours = confirm_sas_in(&mut state(), &remote.id.0, now_ms()).unwrap();
        assert_eq!(ours.len(), 1);
        assert_eq!(
            confirm_sas_in(&mut state(), &remote.id.0, now_ms()).unwrap_err(),
            ERR_WRONG_STATE
        );
        assert_eq!(state_in(&state(), &remote.id.0), Some("handshaking"));

        // CONTACT_ESTABLISHED on both sides: the scanner starts the PNP-002 handshake.
        let confirm = remote.open(&seal_ours(&remote.id, HANDSHAKE, sent(&ours[0]), None));
        let hs_init = only_send(remote.on_message(&confirm));
        let envelope = remote.seal(&me, HANDSHAKE, &hs_init, false);
        let (_, payload) = open_ours(&remote.id, &envelope);
        let steps = on_message_in(&mut state(), &remote.id.0, &payload, now_ms()).unwrap();
        let [hs_resp, Step::Session] = &steps[..] else {
            panic!("expected HandshakeResponse and the session, got {steps:?}");
        };
        // The response still travels under the bootstrap session; then the new one is used.
        let hs_resp = remote.open(&seal_ours(&remote.id, HANDSHAKE, sent(hs_resp), None));
        install_session_in(&mut state(), &remote.id.0).unwrap();
        assert_eq!(
            install_session_in(&mut state(), &remote.id.0).unwrap_err(),
            ERR_NO_PAIRING
        );
        assert_eq!(state_in(&state(), &remote.id.0), Some("accepted"));

        let mut outputs = remote.on_message(&hs_resp).into_iter();
        let Some(PairingOutput::Session(session)) = outputs.next() else {
            panic!("the scanner gets its session");
        };
        assert!(matches!(
            outputs.next(),
            Some(PairingOutput::Established { sas_verified: true })
        ));
        remote.session = Some(*session);

        // The session's first message makes our side ESTABLISHED.
        let first = remote.seal(&me, CONTROL, b"", false);
        assert_eq!(open_ours(&remote.id, &first), (CONTROL, Vec::new()));
        assert_eq!(
            first_message_in(&mut state(), &remote.id.0),
            vec![Step::Established { sas_verified: true }]
        );
        assert_eq!(state_in(&state(), &remote.id.0), None);
        assert!(!abort_in(&mut state(), &remote.id.0));

        // Content flows both ways under the PNP-002 session.
        let hello = remote.open(&seal_ours(&remote.id, TEXT, &hex::encode("hello"), None));
        assert_eq!(hello, b"hello");
        let reply = remote.seal(&me, TEXT, b"hi", false);
        assert_eq!(open_ours(&remote.id, &reply), (TEXT, b"hi".to_vec()));
    }

    #[test]
    #[serial]
    fn this_side_scans_a_code_without_a_sas() {
        let (me, my_ik) = fresh();
        let mut remote = Remote::new();
        let shown = bootstrap::generate_qr_payload_with_ratchet(&remote.ik, None).unwrap();

        // The pasted form (underscores for blanks) is taken as well as the QR text.
        let pasted = format!("  {}\n", bootstrap::qr_text_for_copying(&shown.text));
        let started = initiate_in(&mut state(), &pasted, false, now_ms()).unwrap();
        assert_eq!(started.peer_id, hex::encode(remote.id.0));
        assert_eq!(started.identity_key, hex::encode(remote.ik));
        assert_eq!(state_in(&state(), &remote.id.0), Some("secret_shared"));

        // The bootstrap-completing envelope carries our identity key (PNP-001-MUST-063).
        let envelope = seal_ours(
            &remote.id,
            HANDSHAKE,
            &started.init_hex,
            Some(hex::encode(my_ik)),
        );
        let bs = bootstrap::derive_bootstrap_secret(&shown.seed, &remote.ik, &my_ik).unwrap();
        remote.session = Some(
            DoubleRatchetSession::initialize_responder(
                bs,
                StaticSecret::from(shown.ratchet_secret),
            )
            .unwrap(),
        );
        let init = remote.open(&envelope);
        let (pairing, outputs) = Pairing::respond(
            &remote.identity,
            &BootstrapKey::Seed(&shown.seed),
            &init,
            Some(&my_ik),
            &mut remote.nonces,
            false,
            now_ms(),
        )
        .unwrap();
        remote.pairing = Some(pairing);
        let resp = remote.seal(&me, HANDSHAKE, &only_send(outputs), false);

        // No SAS on either side: straight to the PNP-002 handshake.
        let (_, payload) = open_ours(&remote.id, &resp);
        let steps = on_message_in(&mut state(), &remote.id.0, &payload, now_ms()).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(state_in(&state(), &remote.id.0), Some("handshaking"));
        let hs_init = remote.open(&seal_ours(&remote.id, HANDSHAKE, sent(&steps[0]), None));
        let mut outputs = remote.on_message(&hs_init).into_iter();
        let Some(PairingOutput::Send(hs_resp)) = outputs.next() else {
            panic!("the presenter answers the HandshakeInit");
        };
        let Some(PairingOutput::Session(session)) = outputs.next() else {
            panic!("the presenter gets its session");
        };
        let envelope = remote.seal(&me, HANDSHAKE, &hs_resp, false);
        remote.session = Some(*session);

        let (_, payload) = open_ours(&remote.id, &envelope);
        let steps = on_message_in(&mut state(), &remote.id.0, &payload, now_ms()).unwrap();
        assert_eq!(
            steps,
            vec![
                Step::Session,
                Step::Established {
                    sas_verified: false
                }
            ]
        );
        install_session_in(&mut state(), &remote.id.0).unwrap();
        assert_eq!(state_in(&state(), &remote.id.0), None);

        // PNP-002-MUST-021: our first message confirms the session to the presenter.
        let first = remote.open(&seal_ours(&remote.id, CONTROL, "", None));
        assert!(first.is_empty());
        assert!(matches!(
            remote.pairing.as_mut().unwrap().on_first_message()[..],
            [PairingOutput::Established {
                sas_verified: false
            }]
        ));
    }

    #[test]
    #[serial]
    fn codes_are_refused_with_the_reason() {
        fresh();
        let own = create_code_in(&mut state(), None).unwrap();
        let refused =
            |text: &str, now_ms: u64| initiate_in(&mut state(), text, true, now_ms).unwrap_err();
        assert_eq!(refused(&own.code, now_ms()), ERR_OWN_CODE);
        assert_eq!(refused("not a code", now_ms()), ERR_CODE_INVALID);
        assert_eq!(refused("", now_ms()), ERR_CODE_INVALID);

        let remote = Remote::new();
        let shown = bootstrap::generate_qr_payload_with_ratchet(&remote.ik, None).unwrap();
        // 30 minutes after its timestamp, and not a second longer (PNP-003-MUST-011).
        let ts = bootstrap::parse_qr_text(&shown.text).unwrap().ts;
        let last = (ts + bootstrap::QR_MAX_AGE_SECS) * 1000;
        assert_eq!(refused(&shown.text, last + 1000), ERR_CODE_EXPIRED);
        // Dated far ahead of this device's clock: not expired, not usable.
        assert_eq!(refused(&shown.text, 1_000_000), ERR_CODE_INVALID);
        // Nothing was kept of the refused codes.
        assert!(!has_session(&hex::encode(remote.id.0)));
        assert_eq!(state_in(&state(), &remote.id.0), None);
        // A cut-off code is not one.
        assert_eq!(
            refused(&shown.text[..shown.text.len() / 2], now_ms()),
            ERR_CODE_INVALID
        );
        assert!(initiate_in(&mut state(), &shown.text, true, last).is_ok());
    }

    #[test]
    #[serial]
    fn only_the_scanner_of_the_code_on_display_is_answered() {
        let (me, my_ik) = fresh();
        let code = create_code_in(&mut state(), None).unwrap();
        let blob = export_pending_bootstrap().unwrap();
        let mut remote = Remote::new();
        let envelope = remote.scan(&code.code, &me, true);

        // Arrived on somebody else's connection.
        let other = Remote::new();
        assert!(respond_in(&mut state(), &other.id, &envelope, true, now_ms()).is_err());
        // Made with another code of ours.
        let stale = bootstrap::generate_qr_payload_with_ratchet(&my_ik, None).unwrap();
        let mut forger = Remote::new();
        let forged = forger.scan(&stale.text, &me, true);
        assert!(respond_in(&mut state(), &forger.id, &forged, true, now_ms()).is_err());
        // Nothing moved: the code is still valid and nobody has a session.
        assert_eq!(export_pending_bootstrap().as_deref(), Some(blob.as_str()));
        assert!(!has_session(&hex::encode(other.id.0)));
        assert!(!has_session(&hex::encode(forger.id.0)));

        // The code survives a reload (same identity, empty state) and still pairs.
        let secret = export_secret_key().ok().unwrap();
        panic_wipe();
        assert!(export_pending_bootstrap().is_none());
        initialize_from_key(&secret).ok().unwrap();
        import_pending_bootstrap(&blob).ok().unwrap();
        let responded = respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).unwrap();
        assert!(responded.accepted);
        // One bootstrap per code: the same envelope again finds no code.
        assert!(respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).is_err());
        clear_pending_bootstrap();
    }

    #[test]
    #[serial]
    fn a_first_message_that_is_not_a_valid_handshake_spends_the_code_and_keeps_nothing() {
        let (me, _) = fresh();

        // The holder of the code sends content instead of a BootstrapHandshake.
        let code = create_code_in(&mut state(), None).unwrap();
        let mut remote = Remote::new();
        remote.scan(&code.code, &me, true);
        let envelope = remote.seal(&me, TEXT, b"hello", true);
        let responded = respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).unwrap();
        assert!(!responded.accepted);
        assert_eq!(responded.reason, Some("failed"));
        assert!(responded.steps.is_empty());
        assert!(export_pending_bootstrap().is_none());
        assert!(!has_session(&hex::encode(remote.id.0)));
        assert_eq!(state_in(&state(), &remote.id.0), None);

        // A BootstrapHandshake whose proof is made with another secret (PNP-003-MUST-022).
        let code = create_code_in(&mut state(), None).unwrap();
        let mut remote = Remote::new();
        remote.scan(&code.code, &me, true);
        let (_, forged) = Pairing::initiate(
            &remote.identity,
            &mut [7u8; 32],
            try_decode_32(&get_public_key()).unwrap(),
            true,
            now_ms(),
        )
        .unwrap();
        let envelope = remote.seal(&me, HANDSHAKE, &forged, true);
        let responded = respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).unwrap();
        assert!(!responded.accepted);
        assert_eq!(responded.reason, Some("proof-failed"));
        assert!(!has_session(&hex::encode(remote.id.0)));
    }

    #[test]
    #[serial]
    fn an_aborted_or_timed_out_pairing_leaves_no_session() {
        let (me, _) = fresh();
        let pair = || {
            let code = create_code_in(&mut state(), None).unwrap();
            let mut remote = Remote::new();
            let envelope = remote.scan(&code.code, &me, true);
            let responded =
                respond_in(&mut state(), &remote.id, &envelope, true, now_ms()).unwrap();
            assert!(responded.accepted);
            remote
        };

        // The user says the codes differ.
        let remote = pair();
        assert!(abort_in(&mut state(), &remote.id.0));
        assert!(!has_session(&hex::encode(remote.id.0)));
        assert_eq!(state_in(&state(), &remote.id.0), None);
        assert!(!abort_in(&mut state(), &remote.id.0));
        assert_eq!(
            confirm_sas_in(&mut state(), &remote.id.0, now_ms()).unwrap_err(),
            ERR_NO_PAIRING
        );

        // A wrong SAS confirmation from the peer (PNP-003-MUST-029).
        let mut remote = pair();
        let wrong = parolnet_core::bootstrap::pairing::SasVerify {
            msg_type: parolnet_core::bootstrap::pairing::SAS_CONFIRM,
            sas_mac: vec![0u8; 32],
            nonce: vec![1u8; 16],
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&wrong, &mut payload).unwrap();
        assert_eq!(
            on_message_in(&mut state(), &remote.id.0, &payload, now_ms()).unwrap_err(),
            "sas-mismatch"
        );
        assert!(!has_session(&hex::encode(remote.id.0)));
        assert_eq!(
            on_message_in(&mut state(), &remote.id.0, &payload, now_ms()).unwrap_err(),
            ERR_NO_PAIRING
        );
        remote.pairing = None;

        // Nobody answers the SAS for 10 minutes (§4).
        let remote = pair();
        let later = now_ms() + 9 * 60 * 1000;
        assert!(timeouts_in(&mut state(), later).is_empty());
        let later = now_ms() + 10 * 60 * 1000 + 1000;
        assert_eq!(timeouts_in(&mut state(), later), vec![remote.id.0]);
        assert!(!has_session(&hex::encode(remote.id.0)));
        assert!(timeouts_in(&mut state(), later).is_empty());

        // A wipe takes pairings with it.
        let remote = pair();
        panic_wipe();
        assert_eq!(state_in(&state(), &remote.id.0), None);
    }

    #[test]
    #[serial]
    fn a_passphrase_pairs_without_a_code() {
        let (_, my_ik) = fresh();
        let issued = passphrase_issue_in(&mut state()).unwrap();
        assert_eq!(issued.words, 8);
        assert_eq!(issued.entropy_bits, 88);
        assert_eq!(issued.phrase.split(' ').count(), 8);
        assert_eq!(passphrase::validate(&issued.phrase).unwrap(), 8);
        assert!(passphrase::validate("abandon ability able").is_err());

        // A peer that was told other words is not answered, and the passphrase stays.
        let mut remote = Remote::new();
        let (_, guess) =
            Pairing::initiate(&remote.identity, &mut [9u8; 32], my_ik, false, now_ms()).unwrap();
        assert_eq!(
            respond_passphrase_in(&mut state(), &guess, false, now_ms()).unwrap_err(),
            "proof-failed"
        );

        // The peer that was told the words (and our identity key with them).
        let mut payload = PassphrasePayload::from_text(&issued.payload).unwrap();
        assert_eq!(payload.identity_key(), my_ik);
        let mut bs =
            passphrase::derive_bootstrap_secret(&mut payload.phrase, &remote.ik, &my_ik).unwrap();
        let (pairing, init) =
            Pairing::initiate(&remote.identity, &mut bs, my_ik, false, now_ms()).unwrap();
        remote.pairing = Some(pairing);
        let responded = respond_passphrase_in(&mut state(), &init, false, now_ms()).unwrap();
        assert!(responded.accepted);
        assert_eq!(responded.identity_key, Some(hex::encode(remote.ik)));
        // Spent: a second peer with the same words is not answered.
        assert!(respond_passphrase_in(&mut state(), &init, false, now_ms()).is_err());

        let resp = hex::decode(sent(&responded.steps[0])).unwrap();
        let hs_init = only_send(remote.on_message(&resp));
        let steps = on_message_in(&mut state(), &remote.id.0, &hs_init, now_ms()).unwrap();
        let [hs_resp, Step::Session] = &steps[..] else {
            panic!("expected HandshakeResponse and the session, got {steps:?}");
        };
        install_session_in(&mut state(), &remote.id.0).unwrap();
        let mut outputs = remote
            .on_message(&hex::decode(sent(hs_resp)).unwrap())
            .into_iter();
        let Some(PairingOutput::Session(session)) = outputs.next() else {
            panic!("the peer gets its session");
        };
        remote.session = Some(*session);
        let (me, _) = (PeerId::from_public_key(&my_ik), ());
        let first = remote.seal(&me, CONTROL, b"", false);
        assert_eq!(open_ours(&remote.id, &first), (CONTROL, Vec::new()));
        assert_eq!(
            first_message_in(&mut state(), &remote.id.0),
            vec![Step::Established {
                sas_verified: false
            }]
        );

        // The other direction: this side was told a contact's words.
        let theirs = passphrase::generate();
        let text = PassphrasePayload::new(&remote.ik, &theirs.phrase)
            .unwrap()
            .to_text()
            .unwrap();
        assert_eq!(
            initiate_passphrase_in(&mut state(), "nonsense", false, now_ms()).unwrap_err(),
            ERR_CODE_INVALID
        );
        let started = initiate_passphrase_in(&mut state(), &text, false, now_ms()).unwrap();
        let mut phrase = theirs.phrase.to_string();
        let stretched = StretchedPassphrase::stretch(&mut phrase).unwrap();
        let (_, outputs) = Pairing::respond(
            &remote.identity,
            &BootstrapKey::Passphrase(&stretched),
            &hex::decode(&started.init_hex).unwrap(),
            Some(&my_ik),
            &mut remote.nonces,
            false,
            now_ms(),
        )
        .unwrap();
        let steps =
            on_message_in(&mut state(), &remote.id.0, &only_send(outputs), now_ms()).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(state_in(&state(), &remote.id.0), Some("handshaking"));
    }
}
