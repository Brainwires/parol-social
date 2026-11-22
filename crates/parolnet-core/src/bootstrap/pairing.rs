//! The authenticated first contact of a bootstrap (PNP-003 §3.3, §3.4, §4, §5.4, §5.5) and
//! its hand-over to the PNP-002 handshake.
//!
//! A [`Pairing`] is one bootstrap between two peers, from SECRET_SHARED on. It is sans-I/O:
//! the caller carries the messages it produces ([`PairingOutput::Send`]) to the other peer
//! (as the payload of a PNP-001 envelope with `msg_type = 0x05` where a session exists, or as
//! frames of a direct connection) and feeds what arrives to [`Pairing::on_message`].
//!
//! ```text
//! initiator (scanned the code)                 responder (showed the code)
//!   BOOTSTRAP_INIT  {ik, ek, proof, nonce, prekey_bundle} ───────────▶  verify proof
//!   verify proof  ◀─────────── BOOTSTRAP_RESP {ik, ek, proof, nonce, prekey_bundle}
//!                         AUTHENTICATED on both sides
//!   [SAS requested by either: both show the SAS, each user confirms]
//!   SAS_CONFIRM {sas_mac, nonce} ◀──────────────────────────────────▶  SAS_CONFIRM
//!                       CONTACT_ESTABLISHED on both sides
//!   PNP-002 HandshakeInit (X3DH on the responder's bundle) ──────────▶
//!                 ◀────────── PNP-002 HandshakeResponse {ratchet_key}
//!   first Double Ratchet message ────────────────────────────────────▶
//!                 ESTABLISHED: seed and Bootstrap Secret are erased
//! ```
//!
//! Any failure aborts the pairing: its state becomes [`PairingState::Aborted`] and the
//! Bootstrap Secret and every key it held are erased (§4: "Abort, erase BS").

use super::{compute_bootstrap_proof, sas_digits, sas_emoji, sas_material};
use crate::CoreError;
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::identity::{OneTimePreKeyPair, SignedPreKey};
use parolnet_crypto::kdf::hkdf_sha256;
use parolnet_crypto::x3dh::X3dhKeyAgreement;
use parolnet_crypto::{
    Aead as _, IdentityKeyPair, KeyAgreement as _, OneTimePreKey, PreKeyBundle, X3dhHeader,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// `type` of a BootstrapHandshake sent by the peer that scanned the code.
pub const BOOTSTRAP_INIT: u8 = 0x10;
/// `type` of the BootstrapHandshake that answers it.
pub const BOOTSTRAP_RESP: u8 = 0x11;
/// `type` of a SASVerify message.
pub const SAS_CONFIRM: u8 = 0x12;
/// `type` of a PNP-002 HandshakeInit.
pub const HANDSHAKE_INIT: u8 = 0x01;
/// `type` of a PNP-002 HandshakeResponse.
pub const HANDSHAKE_RESPONSE: u8 = 0x02;
/// PNP-001 `msg_type` of the envelope these messages travel in.
pub const MSG_TYPE_HANDSHAKE: u8 = 0x05;

/// SECRET_SHARED times out after 5 minutes (§4).
pub const SECRET_SHARED_TIMEOUT_MS: u64 = 5 * 60 * 1000;
/// SAS_PENDING times out after 10 minutes (§4).
pub const SAS_TIMEOUT_MS: u64 = 10 * 60 * 1000;
/// The PNP-002 handshake times out after 60 seconds (PNP-002 §4).
pub const HANDSHAKE_TIMEOUT_MS: u64 = 60 * 1000;

/// Why a pairing was aborted or a message refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("malformed bootstrap message")]
    Malformed,
    #[error("the bootstrap proof did not verify")]
    ProofFailed,
    #[error("the bootstrap handshake nonce was seen before")]
    Replay,
    #[error("the pre-key bundle is not signed by the peer's identity key")]
    BadPreKeyBundle,
    #[error("the SAS confirmation did not verify")]
    SasMismatch,
    #[error("the user rejected the SAS")]
    SasRejected,
    #[error("the pairing timed out")]
    Timeout,
    #[error("not expected in this state")]
    WrongState,
    #[error("the PNP-002 handshake failed: {0}")]
    Handshake(String),
}

impl From<CoreError> for PairingError {
    fn from(e: CoreError) -> Self {
        PairingError::Handshake(e.to_string())
    }
}

impl From<parolnet_crypto::CryptoError> for PairingError {
    fn from(e: parolnet_crypto::CryptoError) -> Self {
        PairingError::Handshake(e.to_string())
    }
}

/// One-time pre-key of a [`WirePreKeyBundle`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireOneTimePreKey {
    pub id: u32,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

/// PreKeyBundle as PNP-002 §3.1 puts it on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePreKeyBundle {
    #[serde(with = "serde_bytes")]
    pub ik: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub spk: Vec<u8>,
    pub spk_id: u32,
    #[serde(with = "serde_bytes")]
    pub spk_sig: Vec<u8>,
    pub opks: Vec<WireOneTimePreKey>,
}

impl WirePreKeyBundle {
    fn from_bundle(b: &PreKeyBundle) -> Self {
        WirePreKeyBundle {
            ik: b.identity_key.to_vec(),
            spk: b.signed_prekey.to_vec(),
            spk_id: b.signed_prekey_id,
            spk_sig: b.signed_prekey_sig.clone(),
            opks: b
                .one_time_prekeys
                .iter()
                .map(|o| WireOneTimePreKey {
                    id: o.id,
                    key: o.key.to_vec(),
                })
                .collect(),
        }
    }

    /// The bundle, once its lengths are right, its identity key is `sender_ik` and its
    /// signed pre-key is signed by that key (PNP-002-MUST-003).
    pub fn verified(&self, sender_ik: &[u8; 32]) -> Result<PreKeyBundle, PairingError> {
        use ed25519_dalek::Verifier as _;
        let bad = || PairingError::BadPreKeyBundle;
        let ik: [u8; 32] = self.ik.as_slice().try_into().map_err(|_| bad())?;
        let spk: [u8; 32] = self.spk.as_slice().try_into().map_err(|_| bad())?;
        let sig: [u8; 64] = self.spk_sig.as_slice().try_into().map_err(|_| bad())?;
        if ik != *sender_ik || self.opks.len() > 8 {
            return Err(bad());
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&ik).map_err(|_| bad())?;
        let mut signed = [0u8; 36];
        signed[..32].copy_from_slice(&spk);
        signed[32..].copy_from_slice(&self.spk_id.to_be_bytes());
        key.verify(&signed, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| bad())?;
        let mut one_time_prekeys = Vec::with_capacity(self.opks.len());
        for o in &self.opks {
            one_time_prekeys.push(OneTimePreKey {
                id: o.id,
                key: o.key.as_slice().try_into().map_err(|_| bad())?,
            });
        }
        Ok(PreKeyBundle {
            identity_key: ik,
            signed_prekey: spk,
            signed_prekey_id: self.spk_id,
            signed_prekey_sig: sig.to_vec(),
            one_time_prekeys,
        })
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// BootstrapHandshake (PNP-003 §3.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapHandshake {
    /// [`BOOTSTRAP_INIT`] or [`BOOTSTRAP_RESP`].
    #[serde(rename = "type")]
    pub msg_type: u8,
    /// Sender's Ed25519 identity public key.
    #[serde(with = "serde_bytes")]
    pub ik: Vec<u8>,
    /// Ephemeral X25519 public key.
    #[serde(with = "serde_bytes")]
    pub ek: Vec<u8>,
    /// `HMAC-SHA-256(BS, ik || ek || nonce)`.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// 128-bit random nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Sender's pre-key bundle (PNP-002 §3.1).
    pub prekey_bundle: WirePreKeyBundle,
    /// The sender requests SAS verification (§5.5 step 1). Not one of §3.3's fields: the
    /// spec has no message that tells a peer the other one requested (or skipped) the SAS,
    /// and both must agree on it to reach CONTACT_ESTABLISHED together. A receiver that does
    /// not know the field ignores it; absent means "not requested".
    #[serde(default, skip_serializing_if = "is_false")]
    pub sas: bool,
}

/// SASVerify (PNP-003 §3.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SasVerify {
    /// [`SAS_CONFIRM`].
    #[serde(rename = "type")]
    pub msg_type: u8,
    /// `HMAC-SHA-256(session_key, sas_string || "confirm")`; the session key of a bootstrap
    /// is its Bootstrap Secret.
    #[serde(with = "serde_bytes")]
    pub sas_mac: Vec<u8>,
    /// 128-bit random nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

/// PNP-002 HandshakeInit (§3.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    #[serde(rename = "type")]
    pub msg_type: u8,
    #[serde(with = "serde_bytes")]
    pub ik_a: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ek_a: Vec<u8>,
    pub spk_id_b: u32,
    pub opk_id_b: Option<u32>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub aead_algo: u8,
}

/// PNP-002 HandshakeResponse (§3.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    #[serde(rename = "type")]
    pub msg_type: u8,
    #[serde(with = "serde_bytes")]
    pub ik_b: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ek_b: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ratchet_key: Vec<u8>,
}

#[derive(Deserialize)]
struct TypeOnly {
    #[serde(rename = "type")]
    msg_type: u8,
}

/// The `type` field of a handshake payload, if it is a CBOR map with one.
pub fn message_type(payload: &[u8]) -> Option<u8> {
    ciborium::from_reader::<TypeOnly, _>(payload)
        .ok()
        .map(|t| t.msg_type)
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, PairingError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| PairingError::Malformed)?;
    Ok(buf)
}

fn from_cbor<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, PairingError> {
    ciborium::from_reader(data).map_err(|_| PairingError::Malformed)
}

fn arr<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PairingError> {
    bytes.try_into().map_err(|_| PairingError::Malformed)
}

/// What the Bootstrap Secret is derived from on the side that does not know the other
/// peer's identity key until its BootstrapHandshake arrives.
pub enum BootstrapKey<'a> {
    /// The seed of a QR payload (§5.1 step 7).
    Seed(&'a [u8; 32]),
    /// A stretched passphrase (§5.2 step 3).
    Passphrase(&'a super::passphrase::StretchedPassphrase),
}

impl BootstrapKey<'_> {
    fn bootstrap_secret(
        &self,
        our_ik: &[u8; 32],
        their_ik: &[u8; 32],
    ) -> Result<[u8; 32], CoreError> {
        match self {
            BootstrapKey::Seed(seed) => super::derive_bootstrap_secret(seed, our_ik, their_ik),
            BootstrapKey::Passphrase(p) => p.bootstrap_secret(our_ik, their_ik),
        }
    }
}

/// Which end of the bootstrap this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Scanned the code (or entered the passphrase): sends BOOTSTRAP_INIT.
    Initiator,
    /// Showed the code: answers with BOOTSTRAP_RESP. "Alice" of the SAS computation.
    Responder,
}

/// Where a pairing stands (§4, then PNP-002 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingState {
    /// BS derived, BOOTSTRAP_INIT sent, the answer not verified yet.
    SecretShared,
    /// Proofs verified, SAS requested: waiting for both users to confirm it.
    SasPending,
    /// CONTACT_ESTABLISHED, PNP-002 handshake under way: the initiator sent its
    /// HandshakeInit (OFFERED), the responder waits for it.
    Handshaking,
    /// The responder answered the HandshakeInit and waits for the first Double Ratchet
    /// message (PNP-002 ACCEPTED).
    Accepted,
    /// The PNP-002 session is ESTABLISHED; seed and Bootstrap Secret are erased.
    Established,
    /// Aborted: back to NO_CONTACT, everything erased.
    Aborted,
}

/// The Short Authentication String of a pairing (§5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sas {
    /// The 6-digit decimal SAS.
    pub digits: String,
    /// The emoji SAS: 5 of 256 emoji.
    pub emoji: [char; 5],
}

/// What the caller has to do after a step.
pub enum PairingOutput {
    /// Send this handshake message to the peer.
    Send(Vec<u8>),
    /// SAS_PENDING: display this SAS to the user (PNP-003-MUST-026) and ask whether it
    /// matches what the other peer shows ([`Pairing::confirm_sas`], [`Pairing::reject_sas`]).
    ShowSas(Sas),
    /// The PNP-002 session: use it for the peer from now on, in place of any earlier one.
    /// For the initiator it comes with [`PairingOutput::Established`], and its first message
    /// must be sent now (PNP-002-MUST-021).
    Session(Box<DoubleRatchetSession>),
    /// The PNP-002 session is ESTABLISHED and the bootstrap is over.
    Established {
        /// Both users confirmed the SAS.
        sas_verified: bool,
    },
}

/// One bootstrap between two peers. See the module documentation.
pub struct Pairing {
    role: Role,
    state: PairingState,
    identity: Option<IdentityKeyPair>,
    our_ik: [u8; 32],
    their_ik: [u8; 32],
    bs: Option<Zeroizing<[u8; 32]>>,
    our_ek: [u8; 32],
    their_ek: Option<[u8; 32]>,
    spk: Option<SignedPreKey>,
    opk: Option<OneTimePreKeyPair>,
    peer_bundle: Option<PreKeyBundle>,
    request_sas: bool,
    sas_in_play: bool,
    sas: Option<Sas>,
    local_confirmed: bool,
    peer_confirmed: bool,
    sk: Option<Zeroizing<[u8; 32]>>,
    deadline_ms: u64,
}

fn clone_identity(identity: &IdentityKeyPair) -> IdentityKeyPair {
    let mut secret = identity.secret_bytes();
    let copy = IdentityKeyPair::from_secret_bytes(&secret);
    secret.zeroize();
    copy
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

fn fresh_public_key() -> [u8; 32] {
    *PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).as_bytes()
}

fn verify_proof(
    bs: &[u8; 32],
    ik: &[u8; 32],
    ek: &[u8; 32],
    nonce: &[u8; 16],
    proof: &[u8],
) -> Result<(), PairingError> {
    let expected = compute_bootstrap_proof(bs, ik, ek, nonce)?;
    if bool::from(expected.ct_eq(proof)) {
        Ok(())
    } else {
        Err(PairingError::ProofFailed)
    }
}

/// `HMAC-SHA-256(session_key, sas_string || "confirm")` (§3.4).
pub fn sas_mac(session_key: &[u8; 32], sas_digits: &str) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(session_key)
        .expect("HMAC-SHA-256 takes a key of any length");
    mac.update(sas_digits.as_bytes());
    mac.update(b"confirm");
    mac.finalize().into_bytes().into()
}

type SecretBytes = Zeroizing<Vec<u8>>;

/// `HKDF-SHA-256(salt = SK, ikm = label)`: the PNP-002 §5.2 step 3 key and IV.
fn handshake_key_iv(
    sk: &[u8; 32],
    key_label: &[u8],
    iv_label: &[u8],
) -> Result<(SecretBytes, SecretBytes), PairingError> {
    Ok((
        hkdf_sha256(sk, key_label, b"", 32)?,
        hkdf_sha256(sk, iv_label, b"", 12)?,
    ))
}

impl Pairing {
    fn new(
        role: Role,
        identity: &IdentityKeyPair,
        bs: [u8; 32],
        their_ik: [u8; 32],
        request_sas: bool,
        now_ms: u64,
    ) -> Result<Pairing, PairingError> {
        let spk = SignedPreKey::generate(u32::from_be_bytes(random()), identity)?;
        let opk = OneTimePreKeyPair::generate(u32::from_be_bytes(random()));
        Ok(Pairing {
            role,
            state: PairingState::SecretShared,
            our_ik: identity.public_key_bytes(),
            identity: Some(clone_identity(identity)),
            their_ik,
            bs: Some(Zeroizing::new(bs)),
            our_ek: fresh_public_key(),
            their_ek: None,
            spk: Some(spk),
            opk: Some(opk),
            peer_bundle: None,
            request_sas,
            sas_in_play: false,
            sas: None,
            local_confirmed: false,
            peer_confirmed: false,
            sk: None,
            deadline_ms: now_ms + SECRET_SHARED_TIMEOUT_MS,
        })
    }

    /// Our BootstrapHandshake of `msg_type` (PNP-003-MUST-021: the proof).
    fn our_handshake(&self, msg_type: u8) -> Result<Vec<u8>, PairingError> {
        let (Some(bs), Some(spk), Some(opk)) = (&self.bs, &self.spk, &self.opk) else {
            return Err(PairingError::WrongState);
        };
        let nonce: [u8; 16] = random();
        let proof = compute_bootstrap_proof(bs, &self.our_ik, &self.our_ek, &nonce)?;
        let bundle = PreKeyBundle {
            identity_key: self.our_ik,
            signed_prekey: *spk.public_key.as_bytes(),
            signed_prekey_id: spk.id,
            signed_prekey_sig: spk.signature.to_vec(),
            one_time_prekeys: vec![OneTimePreKey {
                id: opk.id,
                key: *opk.public_key.as_bytes(),
            }],
        };
        to_cbor(&BootstrapHandshake {
            msg_type,
            ik: self.our_ik.to_vec(),
            ek: self.our_ek.to_vec(),
            proof: proof.to_vec(),
            nonce: nonce.to_vec(),
            prekey_bundle: WirePreKeyBundle::from_bundle(&bundle),
            sas: self.request_sas,
        })
    }

    /// Start a bootstrap as the peer that knows both identity keys (it scanned the QR code
    /// or entered the passphrase) and so holds the Bootstrap Secret `bs`. Returns the pairing
    /// and the BOOTSTRAP_INIT to send (PNP-003-MUST-020). `bs` is erased from the caller's
    /// copy.
    pub fn initiate(
        identity: &IdentityKeyPair,
        bs: &mut [u8; 32],
        their_ik: [u8; 32],
        request_sas: bool,
        now_ms: u64,
    ) -> Result<(Pairing, Vec<u8>), PairingError> {
        let pairing = Pairing::new(
            Role::Initiator,
            identity,
            *bs,
            their_ik,
            request_sas,
            now_ms,
        );
        bs.zeroize();
        let pairing = pairing?;
        let init = pairing.our_handshake(BOOTSTRAP_INIT)?;
        Ok((pairing, init))
    }

    /// Answer a BOOTSTRAP_INIT as the peer that showed the code.
    ///
    /// Derives the Bootstrap Secret for the sender's identity key and verifies the proof
    /// (PNP-003-MUST-022); refuses a nonce seen in the last 60 minutes (PNP-003-MUST-043) and
    /// a pre-key bundle the sender's identity key did not sign. `expected_ik` is the
    /// identity key the message is known to come from, where the carrier tells (the
    /// `source_hint` of the envelope it arrived in). On any error nothing is kept: the
    /// candidate Bootstrap Secret is erased.
    ///
    /// On success the pairing is AUTHENTICATED and the outputs hold the BOOTSTRAP_RESP to
    /// send, and the SAS to show if either peer requested it.
    pub fn respond(
        identity: &IdentityKeyPair,
        key: &BootstrapKey<'_>,
        init: &[u8],
        expected_ik: Option<&[u8; 32]>,
        nonces: &mut super::NonceTracker,
        request_sas: bool,
        now_ms: u64,
    ) -> Result<(Pairing, Vec<PairingOutput>), PairingError> {
        let msg: BootstrapHandshake = from_cbor(init)?;
        if msg.msg_type != BOOTSTRAP_INIT {
            return Err(PairingError::Malformed);
        }
        let their_ik: [u8; 32] = arr(&msg.ik)?;
        let their_ek: [u8; 32] = arr(&msg.ek)?;
        let nonce: [u8; 16] = arr(&msg.nonce)?;
        let our_ik = identity.public_key_bytes();
        if expected_ik.is_some_and(|ik| *ik != their_ik) || their_ik == our_ik {
            return Err(PairingError::Malformed);
        }
        let mut bs = key.bootstrap_secret(&our_ik, &their_ik)?;
        let checked = verify_proof(&bs, &their_ik, &their_ek, &nonce, &msg.proof)
            .and_then(|()| {
                if nonces.check_and_record(&nonce, now_ms / 1000) {
                    Ok(())
                } else {
                    Err(PairingError::Replay)
                }
            })
            .and_then(|()| msg.prekey_bundle.verified(&their_ik));
        let bundle = match checked {
            Ok(bundle) => bundle,
            Err(e) => {
                bs.zeroize();
                return Err(e);
            }
        };
        let pairing = Pairing::new(Role::Responder, identity, bs, their_ik, request_sas, now_ms);
        bs.zeroize();
        let mut pairing = pairing?;
        pairing.their_ek = Some(their_ek);
        pairing.peer_bundle = Some(bundle);
        let mut out = vec![PairingOutput::Send(pairing.our_handshake(BOOTSTRAP_RESP)?)];
        pairing.authenticated(msg.sas, now_ms, &mut out)?;
        Ok((pairing, out))
    }

    /// AUTHENTICATED: on to SAS_PENDING when either peer requested the SAS, else straight to
    /// CONTACT_ESTABLISHED ("SAS skipped by both peers").
    fn authenticated(
        &mut self,
        peer_requests_sas: bool,
        now_ms: u64,
        out: &mut Vec<PairingOutput>,
    ) -> Result<(), PairingError> {
        let (Some(bs), Some(their_ek)) = (&self.bs, self.their_ek) else {
            return Err(PairingError::WrongState);
        };
        // Alice presented the code, Bob scanned it (§5.1).
        let material = match self.role {
            Role::Responder => {
                sas_material(bs, &self.our_ik, &self.their_ik, &self.our_ek, &their_ek)?
            }
            Role::Initiator => {
                sas_material(bs, &self.their_ik, &self.our_ik, &their_ek, &self.our_ek)?
            }
        };
        let sas = Sas {
            digits: sas_digits(&material),
            emoji: sas_emoji(&material),
        };
        self.sas = Some(sas.clone());
        self.sas_in_play = self.request_sas || peer_requests_sas;
        if self.sas_in_play {
            self.state = PairingState::SasPending;
            self.deadline_ms = now_ms + SAS_TIMEOUT_MS;
            out.push(PairingOutput::ShowSas(sas));
            Ok(())
        } else {
            self.contact_established(now_ms, out)
        }
    }

    /// CONTACT_ESTABLISHED: the PNP-002 handshake starts (PNP-003-MUST-023). The initiator of
    /// the bootstrap is its Alice: it holds the responder's pre-key bundle.
    fn contact_established(
        &mut self,
        now_ms: u64,
        out: &mut Vec<PairingOutput>,
    ) -> Result<(), PairingError> {
        self.state = PairingState::Handshaking;
        self.deadline_ms = now_ms + HANDSHAKE_TIMEOUT_MS;
        if self.role == Role::Responder {
            return Ok(());
        }
        let (Some(identity), Some(bundle)) = (&self.identity, &self.peer_bundle) else {
            return Err(PairingError::WrongState);
        };
        let agreement = X3dhKeyAgreement {
            identity: clone_identity(identity),
        };
        let (sk, header) = agreement.initiate(bundle)?;
        let (key, iv) = handshake_key_iv(&sk.0, b"ParolNet_init_key", b"ParolNet_init_iv")?;
        let ciphertext =
            ChaCha20Poly1305Cipher::new(&key)?.encrypt(&iv, b"", &self.handshake_aad(&[]))?;
        self.sk = Some(Zeroizing::new(sk.0));
        out.push(PairingOutput::Send(to_cbor(&HandshakeInit {
            msg_type: HANDSHAKE_INIT,
            ik_a: self.our_ik.to_vec(),
            ek_a: header.ephemeral_key.to_vec(),
            spk_id_b: header.signed_prekey_id,
            opk_id_b: header.one_time_prekey_id,
            nonce: random::<16>().to_vec(),
            ciphertext,
            aead_algo: 0x01,
        })?));
        Ok(())
    }

    /// AAD of the handshake ciphertexts: `IK_a || IK_b`, then `extra`.
    fn handshake_aad(&self, extra: &[u8]) -> Vec<u8> {
        let (a, b) = match self.role {
            Role::Initiator => (&self.our_ik, &self.their_ik),
            Role::Responder => (&self.their_ik, &self.our_ik),
        };
        let mut aad = Vec::with_capacity(64 + extra.len());
        aad.extend_from_slice(a);
        aad.extend_from_slice(b);
        aad.extend_from_slice(extra);
        aad
    }

    /// Process a handshake message from the peer.
    ///
    /// `Ok` holds what to do next (nothing, for a message that does not belong to this
    /// state). `Err` means the pairing is aborted and erased: a proof or SAS confirmation
    /// that did not verify (PNP-003-MUST-022, -MUST-029), a replayed nonce, a broken PNP-002
    /// handshake.
    pub fn on_message(
        &mut self,
        payload: &[u8],
        nonces: &mut super::NonceTracker,
        now_ms: u64,
    ) -> Result<Vec<PairingOutput>, PairingError> {
        let result = self.step(payload, nonces, now_ms);
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn step(
        &mut self,
        payload: &[u8],
        nonces: &mut super::NonceTracker,
        now_ms: u64,
    ) -> Result<Vec<PairingOutput>, PairingError> {
        if matches!(
            self.state,
            PairingState::Aborted | PairingState::Established
        ) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        match (message_type(payload), self.role, self.state) {
            (Some(BOOTSTRAP_RESP), Role::Initiator, PairingState::SecretShared) => {
                let msg: BootstrapHandshake = from_cbor(payload)?;
                let ik: [u8; 32] = arr(&msg.ik)?;
                let ek: [u8; 32] = arr(&msg.ek)?;
                let nonce: [u8; 16] = arr(&msg.nonce)?;
                let Some(bs) = &self.bs else {
                    return Err(PairingError::WrongState);
                };
                if ik != self.their_ik {
                    return Err(PairingError::ProofFailed);
                }
                verify_proof(bs, &ik, &ek, &nonce, &msg.proof)?;
                if !nonces.check_and_record(&nonce, now_ms / 1000) {
                    return Err(PairingError::Replay);
                }
                self.peer_bundle = Some(msg.prekey_bundle.verified(&ik)?);
                self.their_ek = Some(ek);
                self.authenticated(msg.sas, now_ms, &mut out)?;
            }
            (Some(SAS_CONFIRM), _, PairingState::SasPending) => {
                let msg: SasVerify = from_cbor(payload)?;
                let (Some(bs), Some(sas)) = (&self.bs, &self.sas) else {
                    return Err(PairingError::WrongState);
                };
                arr::<16>(&msg.nonce)?;
                if !bool::from(sas_mac(bs, &sas.digits).ct_eq(&msg.sas_mac)) {
                    return Err(PairingError::SasMismatch);
                }
                self.peer_confirmed = true;
                if self.local_confirmed {
                    self.contact_established(now_ms, &mut out)?;
                }
            }
            (Some(HANDSHAKE_INIT), Role::Responder, PairingState::Handshaking) => {
                self.on_handshake_init(payload, now_ms, &mut out)?;
            }
            (Some(HANDSHAKE_RESPONSE), Role::Initiator, PairingState::Handshaking) => {
                self.on_handshake_response(payload, &mut out)?;
            }
            // A PNP-002 message while the SAS is still open: the peer went ahead without the
            // confirmation both sides owe each other.
            (Some(HANDSHAKE_INIT | HANDSHAKE_RESPONSE), _, PairingState::SasPending) => {
                return Err(PairingError::WrongState);
            }
            _ => {}
        }
        Ok(out)
    }

    /// PNP-002 §5.3, as Bob.
    fn on_handshake_init(
        &mut self,
        payload: &[u8],
        now_ms: u64,
        out: &mut Vec<PairingOutput>,
    ) -> Result<(), PairingError> {
        let msg: HandshakeInit = from_cbor(payload)?;
        let ik_a: [u8; 32] = arr(&msg.ik_a)?;
        let ek_a: [u8; 32] = arr(&msg.ek_a)?;
        arr::<16>(&msg.nonce)?;
        let bad = |what: &str| PairingError::Handshake(what.into());
        if ik_a != self.their_ik {
            return Err(bad("HandshakeInit from another identity"));
        }
        // 0x00 / absent and 0x01 are ChaCha20-Poly1305, the one cipher this client speaks.
        if msg.aead_algo > 0x01 {
            return Err(bad("unsupported AEAD"));
        }
        let (Some(identity), Some(spk)) = (&self.identity, &self.spk) else {
            return Err(PairingError::WrongState);
        };
        if msg.spk_id_b != spk.id {
            return Err(bad("unknown signed pre-key"));
        }
        // The one-time pre-key is used for this handshake and deleted with it.
        let opk = self.opk.take();
        let opk_secret = match (msg.opk_id_b, &opk) {
            (None, _) => None,
            (Some(id), Some(opk)) if opk.id == id => Some(&opk.private_key),
            _ => return Err(bad("unknown one-time pre-key")),
        };
        let agreement = X3dhKeyAgreement {
            identity: clone_identity(identity),
        };
        let sk = agreement.respond(
            &X3dhHeader {
                identity_key: ik_a,
                ephemeral_key: ek_a,
                signed_prekey_id: msg.spk_id_b,
                one_time_prekey_id: msg.opk_id_b,
            },
            &spk.private_key,
            opk_secret,
        )?;
        let (key, iv) = handshake_key_iv(&sk.0, b"ParolNet_init_key", b"ParolNet_init_iv")?;
        ChaCha20Poly1305Cipher::new(&key)?
            .decrypt(&iv, &msg.ciphertext, &self.handshake_aad(&[]))
            .map_err(|_| bad("HandshakeInit does not verify"))?;

        let ratchet_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ratchet_key = *PublicKey::from(&ratchet_secret).as_bytes();
        let (key, iv) = handshake_key_iv(&sk.0, b"ParolNet_resp_key", b"ParolNet_resp_iv")?;
        let ciphertext = ChaCha20Poly1305Cipher::new(&key)?.encrypt(
            &iv,
            b"",
            &self.handshake_aad(&ratchet_key),
        )?;
        let session = DoubleRatchetSession::initialize_responder(sk.0, ratchet_secret)?;
        out.push(PairingOutput::Send(to_cbor(&HandshakeResponse {
            msg_type: HANDSHAKE_RESPONSE,
            ik_b: self.our_ik.to_vec(),
            ek_b: fresh_public_key().to_vec(),
            nonce: random::<16>().to_vec(),
            ciphertext,
            ratchet_key: ratchet_key.to_vec(),
        })?));
        out.push(PairingOutput::Session(Box::new(session)));
        self.spk = None;
        self.state = PairingState::Accepted;
        self.deadline_ms = now_ms + HANDSHAKE_TIMEOUT_MS;
        Ok(())
    }

    /// PNP-002 §5.4, as Alice.
    fn on_handshake_response(
        &mut self,
        payload: &[u8],
        out: &mut Vec<PairingOutput>,
    ) -> Result<(), PairingError> {
        let msg: HandshakeResponse = from_cbor(payload)?;
        let ik_b: [u8; 32] = arr(&msg.ik_b)?;
        let ratchet_key: [u8; 32] = arr(&msg.ratchet_key)?;
        arr::<32>(&msg.ek_b)?;
        arr::<16>(&msg.nonce)?;
        let bad = |what: &str| PairingError::Handshake(what.into());
        if ik_b != self.their_ik {
            return Err(bad("HandshakeResponse from another identity"));
        }
        let Some(sk) = self.sk.take() else {
            return Err(PairingError::WrongState);
        };
        let (key, iv) = handshake_key_iv(&sk, b"ParolNet_resp_key", b"ParolNet_resp_iv")?;
        ChaCha20Poly1305Cipher::new(&key)?
            .decrypt(&iv, &msg.ciphertext, &self.handshake_aad(&ratchet_key))
            .map_err(|_| bad("HandshakeResponse does not verify"))?;
        let session = DoubleRatchetSession::initialize_initiator(*sk, &ratchet_key)?;
        out.push(PairingOutput::Session(Box::new(session)));
        self.established(out);
        Ok(())
    }

    /// The responder's ACCEPTED → ESTABLISHED: the first Double Ratchet message of the
    /// PNP-002 session arrived and decrypted.
    pub fn on_first_message(&mut self) -> Vec<PairingOutput> {
        let mut out = Vec::new();
        if self.role == Role::Responder && self.state == PairingState::Accepted {
            self.established(&mut out);
        }
        out
    }

    /// ESTABLISHED: the Bootstrap Secret and every bootstrap key are erased
    /// (PNP-003-MUST-024, -MUST-044, -MUST-050).
    fn established(&mut self, out: &mut Vec<PairingOutput>) {
        let sas_verified = self.sas_in_play && self.local_confirmed && self.peer_confirmed;
        self.erase();
        self.state = PairingState::Established;
        out.push(PairingOutput::Established { sas_verified });
    }

    /// The user confirms that the SAS matches: returns the SASVerify to send
    /// (PNP-003-MUST-028), and what follows if the peer's confirmation is already in.
    pub fn confirm_sas(&mut self, now_ms: u64) -> Result<Vec<PairingOutput>, PairingError> {
        if self.state != PairingState::SasPending || self.local_confirmed {
            return Err(PairingError::WrongState);
        }
        let (Some(bs), Some(sas)) = (&self.bs, &self.sas) else {
            return Err(PairingError::WrongState);
        };
        let mut out = vec![PairingOutput::Send(to_cbor(&SasVerify {
            msg_type: SAS_CONFIRM,
            sas_mac: sas_mac(bs, &sas.digits).to_vec(),
            nonce: random::<16>().to_vec(),
        })?)];
        self.local_confirmed = true;
        if self.peer_confirmed
            && let Err(e) = self.contact_established(now_ms, &mut out)
        {
            self.abort();
            return Err(e);
        }
        Ok(out)
    }

    /// The user says the SAS does not match (or refuses to compare): abort and erase
    /// everything (§4: "SAS mismatch / rejection").
    pub fn reject_sas(&mut self) {
        self.abort();
    }

    /// Enforce the timeouts of §4 (SECRET_SHARED 5 minutes, SAS_PENDING 10 minutes) and of
    /// the PNP-002 handshake (60 seconds). `Err(Timeout)` when the pairing just timed out:
    /// it is aborted and erased.
    pub fn check_timeout(&mut self, now_ms: u64) -> Result<(), PairingError> {
        let open = !matches!(
            self.state,
            PairingState::Aborted | PairingState::Established
        );
        if open && now_ms >= self.deadline_ms {
            self.abort();
            return Err(PairingError::Timeout);
        }
        Ok(())
    }

    /// Abort: NO_CONTACT, all state erased.
    pub fn abort(&mut self) {
        self.erase();
        self.state = PairingState::Aborted;
    }

    fn erase(&mut self) {
        self.bs = None; // Zeroizing wipes it
        self.sk = None;
        self.spk = None;
        self.opk = None;
        self.identity = None;
        self.peer_bundle = None;
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The other peer's Ed25519 identity public key.
    pub fn peer_identity_key(&self) -> [u8; 32] {
        self.their_ik
    }

    /// The SAS, from AUTHENTICATED on.
    pub fn sas(&self) -> Option<&Sas> {
        self.sas.as_ref()
    }

    /// Whether the SAS was requested by either peer.
    pub fn sas_requested(&self) -> bool {
        self.sas_in_play
    }

    /// The local user confirmed the SAS and the peer's confirmation is still awaited.
    pub fn awaiting_peer_confirmation(&self) -> bool {
        self.state == PairingState::SasPending && self.local_confirmed && !self.peer_confirmed
    }

    /// Whether the Bootstrap Secret is still held. False once the pairing is ESTABLISHED or
    /// aborted.
    pub fn holds_bootstrap_secret(&self) -> bool {
        self.bs.is_some()
    }

    /// The `bs_hint` of this bootstrap (§3.5), while the Bootstrap Secret is held.
    pub fn bs_hint(&self) -> Option<[u8; 4]> {
        self.bs.as_ref().map(|bs| super::discovery::bs_hint(bs))
    }
}
