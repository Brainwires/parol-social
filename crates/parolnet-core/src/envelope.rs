//! PNP-001 envelope encode / decode helpers.
//!
//! Composes the pieces in `parolnet-crypto` (Double Ratchet AEAD) and
//! `parolnet-protocol` (CBOR codec, bucket padding) into a single high-level
//! API that hands the PWA / transport layer a fully wire-ready byte frame.
//!
//! ## Wire-level padding strategy
//!
//! This module uses strategy (b) from the H1 design note: the envelope's own
//! `padding` field is sized so that the serialized CBOR envelope lands exactly
//! on a bucket boundary.
//!
//! Concretely, for each outgoing message:
//!
//! 1. Build the `CleartextHeader` (version 1, coarsened timestamp, random
//!    message_id, TTL=7).
//! 2. Serialize it via `codec::encode_header` — these bytes are passed to
//!    `DoubleRatchetSession::encrypt_with_aad` as `extra_aad` so the AEAD
//!    tag binds the header (PNP-001-MUST-007).
//! 3. Encrypt the plaintext, producing a `RatchetHeader` + ciphertext.
//! 4. Construct an `Envelope` with `padding = vec![]` and measure its CBOR
//!    length.
//! 5. Pick the smallest bucket B that fits. Compute the padding length so
//!    that `len(serialized_envelope_with_padding) == B`. Because varying the
//!    padding length also varies the CBOR size-prefix of the `padding` bstr,
//!    we account for this analytically by iterating at most twice.
//!
//! Decode is the inverse: CBOR-decode the envelope, then pass the serialized
//! cleartext header bytes (re-encoded from the decoded struct) to
//! `DoubleRatchetSession::decrypt_with_aad` to verify the tag binding.

use parolnet_crypto::RatchetSession;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::codec::{CborCodec, encode_header};
use parolnet_protocol::envelope::{CleartextHeader, Envelope};
use parolnet_protocol::{BUCKET_SIZES, ProtocolCodec};
use rand::RngCore;

use crate::{CoreError, session::SessionManager};

/// Default TTL for outbound envelopes per PNP-001-SHOULD-002.
const DEFAULT_TTL: u8 = 7;

/// Result of decoding + decrypting an envelope.
#[derive(Clone, Debug)]
pub struct DecryptedEnvelope {
    /// Optional source PeerId hint from the cleartext header. Most envelopes
    /// omit this for sender anonymity (PNP-001-SHOULD-003).
    pub source_hint: Option<PeerId>,
    /// Application message type code (PNP-001 §3.4).
    pub msg_type: u8,
    /// Decrypted plaintext bytes (the original message bytes passed to
    /// `encrypt_into_envelope`).
    pub plaintext: Vec<u8>,
    /// Coarsened timestamp from the cleartext header.
    pub timestamp: u64,
}

/// Encrypt `plaintext` into a fully padded PNP-001 wire envelope for
/// transmission to `dest_peer_id` using the given Double Ratchet session.
///
/// Returns the on-wire CBOR bytes; the length is guaranteed to equal exactly
/// one of the bucket sizes (256, 1024, 4096, or 16384). Callers should treat
/// the returned buffer as opaque bytes for transport.
///
/// `msg_type` MUST be one of the codes in the PNP-001 §3.4 registry.
/// `now_secs` is the current wall-clock Unix timestamp; it is coarsened
/// internally.
///
/// `source_hint` is the sender's PeerId to carry in the cleartext header. Per
/// PNP-001-SHOULD-003 this SHOULD be `None` on every envelope except the
/// scanner's bootstrap-completing first frame (PNP-001-MUST-063), where it
/// carries the scanner's 32-byte Ed25519 identity public key packed as a
/// PeerId so the presenter can materialize the responder session (§5.3.1).
pub fn encrypt_into_envelope(
    session: &mut DoubleRatchetSession,
    dest_peer_id: &PeerId,
    msg_type: u8,
    plaintext: &[u8],
    now_secs: u64,
    source_hint: Option<PeerId>,
) -> Result<Vec<u8>, CoreError> {
    // 1. Cleartext header.
    let mut message_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut message_id);
    let cleartext_header = CleartextHeader::new(
        1,
        msg_type,
        *dest_peer_id,
        message_id,
        now_secs,
        DEFAULT_TTL,
        source_hint,
    );

    // 2. Serialize cleartext header for AAD binding.
    let header_bytes = encode_header(&cleartext_header)?;

    // 3. AEAD-encrypt with header bytes bound as extra AAD.
    let (ratchet_header, ciphertext) = session
        .encrypt(plaintext, &header_bytes)
        .map_err(CoreError::Crypto)?;

    // 4. Assemble envelope with zero padding and measure.
    let mut envelope = Envelope {
        cleartext_header,
        ratchet_header,
        encrypted_payload: ciphertext,
        padding: Vec::new(),
    };

    let zero_pad_bytes = CborCodec.encode(&envelope)?;
    let base_len = zero_pad_bytes.len();

    // 5. Pick bucket.
    let bucket = *BUCKET_SIZES.iter().find(|&&b| b >= base_len).ok_or(
        parolnet_protocol::ProtocolError::MessageTooLarge {
            size: base_len,
            max: *BUCKET_SIZES.last().unwrap(),
        },
    )?;

    // Need to solve: encoded_size(envelope_with_padding(n)) == bucket
    //
    // Let f(n) = encoded_size when padding has length n. Empirically f(n) =
    // base_len + n + delta(n), where delta(n) is the CBOR overhead change for
    // the `padding` bstr's length prefix (0 bytes for n=0 case already in
    // base_len). For n in [1, 23] the bstr header is 1 byte (already
    // accounted for when n=0? no — n=0 encodes as 0x40, a 1-byte empty bstr,
    // which IS part of base_len). For n in [24, 255] the bstr header grows
    // by 1 byte; for [256, 65535] by 2 bytes; for [65536, 2^32-1] by 4.
    //
    // The base_len measurement already includes the 1-byte empty-bstr header
    // (0x40). So increasing padding by n ≥ 1 adds n + delta extra bytes where:
    //   delta = 0  if n in 1..=23
    //   delta = 1  if n in 24..=255
    //   delta = 2  if n in 256..=65535
    //   delta = 4  if n in 65536..=4_294_967_295
    let mut pad_len = compute_pad_len(base_len, bucket);
    envelope.padding = vec![0u8; pad_len];

    // Verify — one fixpoint iteration to absorb any delta miscalculation.
    let bytes = CborCodec.encode(&envelope)?;
    if bytes.len() == bucket {
        // Fill padding with CSPRNG bytes so padding isn't predictable.
        rand::thread_rng().fill_bytes(&mut envelope.padding);
        return CborCodec.encode(&envelope).map_err(CoreError::Protocol);
    }
    // Adjust and retry once.
    let diff = bucket as isize - bytes.len() as isize;
    let new_len = (pad_len as isize + diff).max(0) as usize;
    pad_len = new_len;
    envelope.padding = vec![0u8; pad_len];
    let bytes = CborCodec.encode(&envelope)?;
    if bytes.len() != bucket {
        return Err(CoreError::SessionError(format!(
            "envelope padding failed to hit bucket {}: got {} bytes",
            bucket,
            bytes.len()
        )));
    }
    rand::thread_rng().fill_bytes(&mut envelope.padding);
    CborCodec.encode(&envelope).map_err(CoreError::Protocol)
}

/// Compute the `padding` length needed so that a CBOR-encoded envelope of
/// `base_len` (with an empty padding bstr) expands to exactly `bucket` bytes.
fn compute_pad_len(base_len: usize, bucket: usize) -> usize {
    debug_assert!(bucket >= base_len);
    let delta_bytes_available = bucket - base_len;
    if delta_bytes_available == 0 {
        return 0;
    }
    // Try each CBOR bstr-header size tier. base_len already counts the 1-byte
    // empty-bstr marker (0x40). Replacing it with a longer bstr adds
    // (header_delta + n) bytes where header_delta depends on n:
    //
    //   n in 1..=23        → total add = n        (major-type-2 + small len
    //                                               in one byte, already 1B)
    //   n in 24..=255      → total add = n + 1
    //   n in 256..=65535   → total add = n + 2
    //   n in 65536..       → total add = n + 4
    if delta_bytes_available <= 23 {
        delta_bytes_available
    } else if delta_bytes_available <= 256 {
        // n + 1 = delta ⇒ n = delta - 1. But if delta-1 in 1..=23, the tier
        // would collapse. Prefer the larger tier:
        delta_bytes_available.saturating_sub(1)
    } else if delta_bytes_available <= 65_537 {
        delta_bytes_available.saturating_sub(2)
    } else {
        delta_bytes_available.saturating_sub(4)
    }
}

/// Decrypt and unpack a PNP-001 envelope previously produced by
/// `encrypt_into_envelope`.
///
/// The caller MUST verify that `envelope_bytes.len()` equals one of the
/// bucket sizes *before* calling this function (PNP-001-MUST-036). The helper
/// re-checks in debug mode but does not enforce in release; length-based
/// rejection is a transport-layer responsibility.
pub fn decrypt_from_envelope(
    session: &mut DoubleRatchetSession,
    envelope_bytes: &[u8],
) -> Result<DecryptedEnvelope, CoreError> {
    if !BUCKET_SIZES.contains(&envelope_bytes.len()) {
        return Err(CoreError::Protocol(
            parolnet_protocol::ProtocolError::InvalidEnvelopeLength(envelope_bytes.len()),
        ));
    }

    let envelope = CborCodec.decode(envelope_bytes)?;

    // Re-serialize the cleartext header to reconstruct the AAD bytes that
    // the sender bound into the AEAD tag.
    let header_bytes = encode_header(&envelope.cleartext_header)?;

    let plaintext = session
        .decrypt(
            &envelope.ratchet_header,
            &envelope.encrypted_payload,
            &header_bytes,
        )
        .map_err(CoreError::Crypto)?;

    Ok(DecryptedEnvelope {
        source_hint: envelope.cleartext_header.source_hint,
        msg_type: envelope.cleartext_header.msg_type,
        plaintext,
        timestamp: envelope.cleartext_header.timestamp,
    })
}

/// Envelope variant that operates against a `SessionManager` handle keyed by
/// destination PeerId. Thin wrapper for the WASM bindings; native callers can
/// use `encrypt_into_envelope` directly.
pub fn encrypt_for_peer(
    sessions: &SessionManager,
    dest_peer_id: &PeerId,
    msg_type: u8,
    plaintext: &[u8],
    now_secs: u64,
    source_hint: Option<PeerId>,
) -> Result<Vec<u8>, CoreError> {
    sessions.with_session_mut(dest_peer_id, |ratchet| {
        encrypt_into_envelope(
            ratchet,
            dest_peer_id,
            msg_type,
            plaintext,
            now_secs,
            source_hint,
        )
    })
}

/// Session-manager variant of `decrypt_from_envelope` keyed by source peer.
pub fn decrypt_for_peer(
    sessions: &SessionManager,
    source_peer_id: &PeerId,
    envelope_bytes: &[u8],
) -> Result<DecryptedEnvelope, CoreError> {
    sessions.with_session_mut(source_peer_id, |ratchet| {
        decrypt_from_envelope(ratchet, envelope_bytes)
    })
}

/// PNP-001 §5.3.1 — materialize a responder Double Ratchet session from the
/// envelope's cleartext `source_hint` and decrypt the envelope atomically.
///
/// Called on the QR-presenter receive path when normal trial-decrypt has
/// exhausted every committed session. Derives the bootstrap shared secret per
/// PNP-003 §5.1 step 7, constructs a **candidate** responder session, and
/// attempts AEAD decryption under it. Only on AEAD success is the candidate
/// session committed to `sessions` keyed by the scanner's PeerId.
///
/// Pins **PNP-001-MUST-064**: AEAD verification precedes session commit, so a
/// forged `source_hint` cannot poison the session manager — the attacker
/// would need the out-of-band `seed` to produce a session whose tag verifies.
///
/// # Arguments
/// - `our_ik` — the presenter's 32-byte Ed25519 identity public key (same
///   value embedded in their QR payload).
/// - `seed` — the 32-byte QR seed from `generate_qr_payload_with_ratchet`.
/// - `our_ratchet_secret` — the X25519 ratchet secret paired to the ratchet
///   public key that was advertised in the QR payload.
///
/// Returns the decrypted envelope on success. On failure, `sessions` and the
/// caller's pending-bootstrap state are untouched — the caller retains the
/// ability to process a subsequent legitimate first-envelope.
pub fn try_bootstrap_and_decrypt(
    sessions: &SessionManager,
    envelope_bytes: &[u8],
    our_ik: &[u8; 32],
    seed: &[u8; 32],
    our_ratchet_secret: &[u8; 32],
) -> Result<DecryptedEnvelope, CoreError> {
    use x25519_dalek::StaticSecret;

    if !BUCKET_SIZES.contains(&envelope_bytes.len()) {
        return Err(CoreError::Protocol(
            parolnet_protocol::ProtocolError::InvalidEnvelopeLength(envelope_bytes.len()),
        ));
    }

    let envelope = CborCodec.decode(envelope_bytes)?;

    // source_hint carries the scanner's 32-byte Ed25519 IK on the bootstrap
    // envelope. Missing = not a bootstrap frame; caller's pending state stays
    // intact.
    let their_ik_peer = envelope.cleartext_header.source_hint.ok_or_else(|| {
        CoreError::BootstrapFailed("envelope has no source_hint; cannot bootstrap".into())
    })?;
    let their_ik = their_ik_peer.0;

    let bs = crate::bootstrap::derive_bootstrap_secret(seed, our_ik, &their_ik)?;

    // Candidate session — held on the stack, not yet in the session manager.
    let ratchet_sk = StaticSecret::from(*our_ratchet_secret);
    let mut candidate = DoubleRatchetSession::initialize_responder(bs, ratchet_sk)
        .map_err(CoreError::Crypto)?;

    let header_bytes = encode_header(&envelope.cleartext_header)?;
    let plaintext = candidate
        .decrypt(
            &envelope.ratchet_header,
            &envelope.encrypted_payload,
            &header_bytes,
        )
        .map_err(CoreError::Crypto)?;

    // AEAD verified → commit session keyed by PeerId(SHA-256(their_ik)).
    let scanner_peer_id = PeerId::from_public_key(&their_ik);
    sessions.add_session(scanner_peer_id, candidate);

    Ok(DecryptedEnvelope {
        source_hint: Some(scanner_peer_id),
        msg_type: envelope.cleartext_header.msg_type,
        plaintext,
        timestamp: envelope.cleartext_header.timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parolnet_crypto::double_ratchet::DoubleRatchetSession;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let bob_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_pub = *PublicKey::from(&bob_sk).as_bytes();
        let alice = DoubleRatchetSession::initialize_initiator([0x42u8; 32], &bob_pub).unwrap();
        let bob = DoubleRatchetSession::initialize_responder([0x42u8; 32], bob_sk).unwrap();
        (alice, bob)
    }

    #[test]
    fn round_trip_small_plaintext() {
        let (mut alice, mut bob) = session_pair();
        let dest = PeerId([0x11u8; 32]);
        let env =
            encrypt_into_envelope(&mut alice, &dest, 0x01, b"hello bob", 1_700_000_000, None)
                .unwrap();
        assert!(BUCKET_SIZES.contains(&env.len()));
        let decoded = decrypt_from_envelope(&mut bob, &env).unwrap();
        assert_eq!(decoded.plaintext, b"hello bob");
        assert_eq!(decoded.msg_type, 0x01);
        assert_eq!(decoded.timestamp, 1_700_000_000 / 300 * 300);
    }

    #[test]
    fn tampered_cleartext_header_fails_aead() {
        let (mut alice, mut bob) = session_pair();
        let dest = PeerId([0x11u8; 32]);
        let mut env =
            encrypt_into_envelope(&mut alice, &dest, 0x01, b"secret", 1_700_000_000, None).unwrap();
        // Flip a byte in the middle — statistically touches the cleartext
        // header (it sits at the front of the CBOR encoding).
        env[10] ^= 0x01;
        assert!(decrypt_from_envelope(&mut bob, &env).is_err());
    }
}
