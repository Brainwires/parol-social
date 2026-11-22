//! Bootstrap protocol implementation (PNP-003).
//!
//! QR code / shared secret key exchange with zero registration breadcrumbs.
//!
//! - this module: the QR payload (§3.1, §5.1), the Bootstrap Secret, the proof, the SAS and
//!   the replay window;
//! - [`base45`]: the QR payload's text form;
//! - [`passphrase`]: the passphrase alternative (§3.2, §5.2, §5.3);
//! - [`pairing`]: the BootstrapHandshake / SASVerify exchange and its state machine (§3.3,
//!   §3.4, §4, §5.4, §5.5), ending in the PNP-002 handshake;
//! - [`discovery`]: the local discovery announcement (§3.5, §5.6).

pub mod base45;
pub mod discovery;
pub mod pairing;
pub mod passphrase;

use crate::CoreError;
use parolnet_crypto::kdf::hkdf_sha256_fixed;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The most characters a QR payload's text form may have, so it fits one QR code
/// (PNP-003-MUST-001).
pub const QR_MAX_CHARS: usize = 2953;

/// Network hints of §3.1.
pub const NET_INTERNET_RELAY: u8 = 0x01;
pub const NET_LAN: u8 = 0x02;
pub const NET_BLUETOOTH: u8 = 0x03;

/// QR code payload (PNP-003 Section 3.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QrPayload {
    /// Protocol version (must be 1).
    pub v: u8,
    /// Ed25519 identity public key of the QR presenter.
    #[serde(with = "serde_bytes")]
    pub ik: Vec<u8>,
    /// 256-bit cryptographically random shared secret seed.
    #[serde(with = "serde_bytes")]
    pub seed: Vec<u8>,
    /// X25519 ratchet public key for Double Ratchet initialization.
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Vec::is_empty")]
    pub rk: Vec<u8>,
    /// Optional relay hint (hostname:port).
    pub relay: Option<String>,
    /// Coarsened timestamp (5-minute bucket).
    pub ts: u64,
    /// Network hint: 1=internet relay, 2=LAN, 3=BT.
    pub net: u8,
}

impl Drop for QrPayload {
    fn drop(&mut self) {
        // PNP-003-MUST-024: the seed does not outlive the bootstrap.
        self.seed.zeroize();
    }
}

/// Result of QR payload generation, including the ratchet secret for session setup.
pub struct QrGenerationResult {
    /// CBOR-encoded QR payload bytes.
    pub payload_bytes: Vec<u8>,
    /// The payload as it goes into the QR code: base45 of the CBOR (PNP-003-MUST-007).
    pub text: String,
    /// X25519 ratchet secret key (caller must store for responder session init).
    pub ratchet_secret: [u8; 32],
    /// The random seed used (caller must store to derive bootstrap secret later).
    pub seed: [u8; 32],
}

impl Drop for QrGenerationResult {
    fn drop(&mut self) {
        // The CBOR and its text carry the seed too.
        self.payload_bytes.zeroize();
        self.text.zeroize();
        self.ratchet_secret.zeroize();
        self.seed.zeroize();
    }
}

/// Base45 text of a CBOR QR payload, refused when it would not fit one QR code
/// (PNP-003-MUST-001, -MUST-007).
pub fn encode_qr_text(cbor: &[u8]) -> Result<String, CoreError> {
    let text = base45::encode(cbor);
    if text.len() > QR_MAX_CHARS {
        return Err(CoreError::BootstrapFailed(format!(
            "QR payload is {} characters; one QR code holds at most {QR_MAX_CHARS}",
            text.len()
        )));
    }
    Ok(text)
}

/// A QR text in the form to show for copying. Base45 has a blank in its alphabet, and blanks
/// at the ends or in a row are what messengers and text fields eat: here every blank is an
/// underscore, which base45 does not use. [`decode_qr_text`] takes both forms.
pub fn qr_text_for_copying(text: &str) -> String {
    text.replace(' ', "_")
}

/// The CBOR bytes of a scanned or pasted QR text: the QR code's own content, or the form
/// made by [`qr_text_for_copying`] (with whatever line breaks, blanks and quotes copying
/// added around or inside it).
pub fn decode_qr_text(text: &str) -> Result<Vec<u8>, CoreError> {
    let clean: String = if text.contains('_') {
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .map(|c| if c == '_' { ' ' } else { c })
            .collect()
    } else {
        text.chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\t' | '"' | '\''))
            .collect()
    };
    if clean.len() > QR_MAX_CHARS {
        return Err(CoreError::BootstrapFailed(format!(
            "QR payload is longer than {QR_MAX_CHARS} characters"
        )));
    }
    base45::decode(&clean)
}

/// Generate a QR code payload for peer introduction.
///
/// Returns the CBOR bytes, their base45 text (what the QR code shows) and the ratchet secret
/// key that the presenter must store to later initialize the responder side of the Double
/// Ratchet. Fails when the payload (a long relay hint) would not fit one QR code.
pub fn generate_qr_payload_with_ratchet(
    identity_key: &[u8; 32],
    relay_hint: Option<&str>,
) -> Result<QrGenerationResult, CoreError> {
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    // PNP-003-MUST-006: a fresh 32-byte seed from the operating system's CSPRNG.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    // Generate X25519 ratchet keypair for Double Ratchet initialization
    let ratchet_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let ratchet_public = PublicKey::from(&ratchet_secret);

    let now_secs = crate::now_epoch_secs();
    let coarsened = (now_secs / 300) * 300;

    let payload = QrPayload {
        v: 1,
        ik: identity_key.to_vec(),
        seed: seed.to_vec(),
        rk: ratchet_public.as_bytes().to_vec(),
        relay: relay_hint.map(|s| s.to_string()),
        ts: coarsened,
        net: if relay_hint.is_some() {
            NET_INTERNET_RELAY
        } else {
            NET_LAN
        },
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| CoreError::BootstrapFailed(format!("CBOR encode: {e}")))?;
    let text = encode_qr_text(&buf)?;

    Ok(QrGenerationResult {
        payload_bytes: buf,
        text,
        ratchet_secret: ratchet_secret.to_bytes(),
        seed,
    })
}

/// Generate a QR code payload for peer introduction (legacy, without ratchet key).
///
/// Returns CBOR-encoded bytes (base45 encoding for actual QR rendering
/// would be applied by the UI layer).
pub fn generate_qr_payload(
    identity_key: &[u8; 32],
    relay_hint: Option<&str>,
) -> Result<Vec<u8>, CoreError> {
    Ok(generate_qr_payload_with_ratchet(identity_key, relay_hint)?
        .payload_bytes
        .clone())
}

/// Parse a scanned QR code's text (base45 of the CBOR payload), validating it against this
/// device's clock (PNP-003-MUST-010, -MUST-011).
pub fn parse_qr_text(text: &str) -> Result<QrPayload, CoreError> {
    parse_qr_text_at(text, crate::now_epoch_secs())
}

/// [`parse_qr_text`] as of `now_secs`.
pub fn parse_qr_text_at(text: &str, now_secs: u64) -> Result<QrPayload, CoreError> {
    let mut cbor = decode_qr_text(text)?;
    let parsed = parse_qr_payload_at(&cbor, now_secs);
    cbor.zeroize();
    parsed
}

/// The relay hint for the next QR code: each code names another of the presenter's relays,
/// so that a relay seen in one code is not the one every contact is sent to
/// (PNP-003-SHOULD-008). `None` when there is no relay to name (PNP-003-MAY-003).
pub fn rotate_relay_hint(relays: &[String], codes_made: u64) -> Option<&str> {
    if relays.is_empty() {
        return None;
    }
    Some(relays[(codes_made % relays.len() as u64) as usize].as_str())
}

/// How far a QR payload's `ts` may be from the scanner's time, either way
/// (30 minutes, PNP-003-MUST-011).
pub const QR_MAX_AGE_SECS: u64 = 1800;

/// The bucket `ts` is coarsened to (PNP-003 §3.1).
const QR_TS_BUCKET_SECS: u64 = 300;

/// Parse a scanned QR code payload from CBOR bytes.
///
/// Validates the timestamp against this device's clock: see
/// [`parse_qr_payload_at`].
pub fn parse_qr_payload(data: &[u8]) -> Result<QrPayload, CoreError> {
    parse_qr_payload_at(data, crate::now_epoch_secs())
}

/// Parse a scanned QR code payload from CBOR bytes, as of `now_secs`.
///
/// PNP-003-MUST-011: `ts` must be within 30 minutes of the current time.
///
/// - A code older than 30 minutes is rejected, measured from `ts` (which the
///   presenter floored to 5 minutes) to `now_secs`. A payload without a
///   timestamp (`ts = 0`) is as old as a code can be.
/// - A code dated more than 30 minutes after the current coarsened time is
///   rejected: a presenter's clock may run that far ahead, and no further, or
///   `ts` would set no bound on how long a code can be scanned.
pub fn parse_qr_payload_at(data: &[u8], now_secs: u64) -> Result<QrPayload, CoreError> {
    let payload: QrPayload = ciborium::from_reader(data)
        .map_err(|e| CoreError::BootstrapFailed(format!("CBOR decode: {e}")))?;

    if payload.v != 1 {
        return Err(CoreError::BootstrapFailed(format!(
            "unsupported version: {}",
            payload.v
        )));
    }
    if payload.ik.len() != 32 {
        return Err(CoreError::BootstrapFailed(
            "identity key must be 32 bytes".into(),
        ));
    }
    if payload.seed.len() != 32 {
        return Err(CoreError::BootstrapFailed("seed must be 32 bytes".into()));
    }
    if !payload.rk.is_empty() && payload.rk.len() != 32 {
        return Err(CoreError::BootstrapFailed(
            "ratchet key must be 32 bytes".into(),
        ));
    }
    if !matches!(payload.net, NET_INTERNET_RELAY | NET_LAN | NET_BLUETOOTH) {
        return Err(CoreError::BootstrapFailed(format!(
            "unknown network hint: {}",
            payload.net
        )));
    }
    if payload.relay.as_deref().is_some_and(str::is_empty) {
        return Err(CoreError::BootstrapFailed("empty relay hint".into()));
    }

    // Reject QR codes older than 30 minutes
    if now_secs.saturating_sub(payload.ts) > QR_MAX_AGE_SECS {
        return Err(CoreError::BootstrapFailed(format!(
            "QR code expired: created {} seconds ago (max {})",
            now_secs.saturating_sub(payload.ts),
            QR_MAX_AGE_SECS
        )));
    }
    // ... and codes dated more than 30 minutes ahead of the current bucket
    let now_bucket = now_secs - now_secs % QR_TS_BUCKET_SECS;
    if payload.ts.saturating_sub(now_bucket) > QR_MAX_AGE_SECS {
        return Err(CoreError::BootstrapFailed(format!(
            "QR code timestamp is {} seconds ahead of this device's clock (max {})",
            payload.ts.saturating_sub(now_bucket),
            QR_MAX_AGE_SECS
        )));
    }

    Ok(payload)
}

/// Derive the Bootstrap Secret from a seed and both peers' identity keys.
///
/// BS = HKDF-SHA-256(
///   salt = "ParolNet_bootstrap_v1",
///   ikm  = seed,
///   info = sorted_concat(IK_alice, IK_bob),
///   len  = 32
/// )
pub fn derive_bootstrap_secret(
    seed: &[u8; 32],
    our_ik: &[u8; 32],
    their_ik: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    // Sort keys so both peers derive the same secret regardless of who scanned
    let mut info = Vec::with_capacity(64);
    if our_ik < their_ik {
        info.extend_from_slice(our_ik);
        info.extend_from_slice(their_ik);
    } else {
        info.extend_from_slice(their_ik);
        info.extend_from_slice(our_ik);
    }

    hkdf_sha256_fixed::<32>(b"ParolNet_bootstrap_v1", seed, &info)
        .map_err(|e| CoreError::BootstrapFailed(format!("HKDF: {e}")))
}

/// Compute the HMAC proof for bootstrap authentication (PNP-003 Section 5.4).
///
/// proof = HMAC-SHA-256(BS, ik || ek || nonce)
pub fn compute_bootstrap_proof(
    bootstrap_secret: &[u8; 32],
    identity_key: &[u8; 32],
    ephemeral_key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], CoreError> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(bootstrap_secret)
        .map_err(|_| CoreError::BootstrapFailed("HMAC init failed".into()))?;
    mac.update(identity_key);
    mac.update(ephemeral_key);
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify a bootstrap proof.
pub fn verify_bootstrap_proof(
    bootstrap_secret: &[u8; 32],
    identity_key: &[u8; 32],
    ephemeral_key: &[u8; 32],
    nonce: &[u8; 16],
    proof: &[u8; 32],
) -> Result<bool, CoreError> {
    use subtle::ConstantTimeEq;
    let expected = compute_bootstrap_proof(bootstrap_secret, identity_key, ephemeral_key, nonce)?;
    Ok(expected.ct_eq(proof).into())
}

/// How long a bootstrap handshake nonce is remembered (60 minutes, PNP-003-MUST-043).
pub const NONCE_WINDOW_SECS: u64 = 60 * 60;

/// The bootstrap handshake nonces seen in the last 60 minutes (PNP-003-MUST-043).
///
/// A handshake whose nonce is in here is a replay and is refused. Nonces older than the
/// window are forgotten. At capacity a new nonce is refused rather than an old one dropped:
/// forgetting a nonce inside its window would let it be replayed.
pub struct NonceTracker {
    /// Nonce and when it was seen (seconds).
    seen: std::collections::HashMap<[u8; 16], u64>,
    max_entries: usize,
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl NonceTracker {
    /// A tracker holding at most `max_entries` nonces at a time.
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            max_entries,
        }
    }

    /// Record `nonce` as seen at `now_secs`. `false` when it was already seen in the last
    /// 60 minutes (a replay), or when the tracker is full of nonces still in their window.
    pub fn check_and_record(&mut self, nonce: &[u8; 16], now_secs: u64) -> bool {
        self.seen
            .retain(|_, at| now_secs.saturating_sub(*at) < NONCE_WINDOW_SECS);
        if self.seen.contains_key(nonce) || self.seen.len() >= self.max_entries {
            return false;
        }
        self.seen.insert(*nonce, now_secs);
        true
    }

    /// Nonces currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// The 5 bytes of SAS material (PNP-003 §5.5 step 2).
///
/// `alice` is the peer that presented the QR code or issued the passphrase (the receiver of
/// BOOTSTRAP_INIT), `bob` the one that scanned or entered it.
pub fn sas_material(
    bootstrap_secret: &[u8; 32],
    ik_alice: &[u8; 32],
    ik_bob: &[u8; 32],
    ek_alice: &[u8; 32],
    ek_bob: &[u8; 32],
) -> Result<[u8; 5], CoreError> {
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(ik_alice);
    ikm.extend_from_slice(ik_bob);
    ikm.extend_from_slice(ek_alice);
    ikm.extend_from_slice(ek_bob);
    hkdf_sha256_fixed::<5>(bootstrap_secret, &ikm, b"ParolNet_SAS_v1")
        .map_err(|e| CoreError::BootstrapFailed(format!("SAS HKDF: {e}")))
}

/// The 6-digit decimal SAS of 5 bytes of SAS material: `uint40 mod 1000000`, zero-padded.
pub fn sas_digits(material: &[u8; 5]) -> String {
    let val = material
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    format!("{:06}", val % 1_000_000)
}

/// The 256 emoji of the emoji SAS (PNP-003-MUST-027), indexed by byte value: four runs of 64
/// consecutive code points (animals, plants and food, activities and places, transport).
pub const SAS_EMOJI: [char; 256] = {
    const STARTS: [u32; 4] = [0x1F400, 0x1F340, 0x1F3A0, 0x1F680];
    let mut table = ['\0'; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = match char::from_u32(STARTS[i / 64] + (i % 64) as u32) {
            Some(c) => c,
            None => panic!("not a code point"),
        };
        i += 1;
    }
    table
};

/// The emoji SAS of 5 bytes of SAS material: one emoji per byte (PNP-003-MUST-027).
pub fn sas_emoji(material: &[u8; 5]) -> [char; 5] {
    material.map(|b| SAS_EMOJI[b as usize])
}

/// Compute a Short Authentication String (SAS) for voice verification.
///
/// Returns a 6-digit decimal string.
pub fn compute_sas(
    bootstrap_secret: &[u8; 32],
    ik_alice: &[u8; 32],
    ik_bob: &[u8; 32],
    ek_alice: &[u8; 32],
    ek_bob: &[u8; 32],
) -> Result<String, CoreError> {
    let material = sas_material(bootstrap_secret, ik_alice, ik_bob, ek_alice, ek_bob)?;
    Ok(sas_digits(&material))
}
